#include <misc/talisman.h>

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/xxhash.h>

#include <linux/module.h>
#include <linux/debugfs.h>

static struct dentry *dir = NULL;
static atomic_t stat_add = ATOMIC_INIT(0);
static atomic_t stat_rm = ATOMIC_INIT(0);
static atomic_t stat_vFail = ATOMIC_INIT(0);
static atomic_t stat_vOkay = ATOMIC_INIT(0);


/* Hash-tables for endorsers */
DEFINE_ENDORSER(aa_fname_tbl, 8);
DEFINE_ENDORSER(exx_task_cred, 8);
DEFINE_ENDORSER(exx_aa_task_label, 8);

// TODO: Make below lsm specific
DEFINE_HASHTABLE(subject_hash_table, 8);  // Note the size here is bits (i.e, 3 = 8 buckets)
DEFINE_HASHTABLE(object_hash_table, 8);

// LSM Specific Object Types
DEFINE_HASHTABLE(inode_hash_table, 8);
DEFINE_HASHTABLE(dentry_hash_table, 8);
DEFINE_HASHTABLE(file_hash_table, 8);
DEFINE_HASHTABLE(superblock_hash_table, 8);
DEFINE_HASHTABLE(ipc_hash_table, 8);
DEFINE_HASHTABLE(key_hash_table, 8);
DEFINE_HASHTABLE(shm_hash_table, 8);
DEFINE_HASHTABLE(sem_hash_table, 8);
DEFINE_HASHTABLE(ns_hash_table, 8);

/* Generic hash table functions */

// Add entry to hash table.
// Caller needs to allocate storage for value using kalloc().
// When removing the node kfree() will be called on the value.
void exx_add(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    struct exx_entry *new;

    /* remove stale entry? */
    // __exx_rm(meta, key);

    /* add new entry */
    new = kmalloc(sizeof(struct exx_entry), GFP_KERNEL);
    if (!new)
        goto fail;
    new->key = key;
    new->val = val;
    new->val_len = val_len;

    write_lock(&meta->lck);
    hlist_add_head(&new->hnode, &meta->tbl[hash_min(key, meta->bits)]);
    write_unlock(&meta->lck);

    /* update stats */
    atomic_inc(&meta->cAdd);
    atomic_inc(&stat_add);
    return;

fail:
    write_unlock(&meta->lck);
    printk(KERN_ERR "Memory allocation failed for subject endorser\n");
}

struct exx_entry *__exx_find(struct exx_meta *meta, __u64 key) {
    struct exx_entry *entry;

    hlist_for_each_entry(entry, &meta->tbl[hash_min(key, meta->bits)], hnode) {
        if (entry->key == key) {
            return entry;
        }
    }
    return NULL;  // Data not found
}

// Verify entry in hash table using memcmp().
// Returns: 1 if found, else 0
// int exx_verify(struct rwlock_t *lck, struct hlist_head *tbl,
int exx_verify(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    struct exx_entry *entry;

    read_lock(&meta->lck);
    entry = __exx_find(meta, key);
    if (!entry)
        goto fail;

    /* compare result */
    if ((entry->val_len == val_len) && memcmp(entry->val, val, val_len)) {
        read_unlock(&meta->lck);
        atomic_inc(&meta->cVokay);
        atomic_inc(&stat_vOkay);
        return 1;
    }

fail:
    read_unlock(&meta->lck);
    atomic_inc(&meta->cVfail);
    atomic_inc(&stat_vFail);
    return 0;
}

void __exx_rm(struct exx_meta *meta, __u64 key) {
    struct exx_entry *entry = __exx_find(meta, key);
    if (entry) {
        hash_del(&entry->hnode);
        kfree(entry->val);
        kfree(entry);

        /* update stats */
        atomic_inc(&meta->cDel);
        atomic_inc(&stat_rm);
    }
}

void exx_rm(struct exx_meta *meta, __u64 key) {
    write_lock(&meta->lck);
    __exx_rm(meta, key);
    write_unlock(&meta->lck);
}

void *exx_dup(void *src, size_t n) {
    void *ptr;

    if (!src)
        return NULL;

    ptr = kmalloc(n, GFP_KERNEL);
    if (!ptr)
        return NULL;

    memcpy(ptr, src, n);
    return ptr;
}

void mount_endorser_debugfs(struct exx_meta *meta)
{
    struct dentry *this = debugfs_create_dir(meta->namestr, dir);
    if (!this)
        return;

    debugfs_create_atomic_t("add", 0666, this, &meta->cAdd);
    debugfs_create_atomic_t("remove", 0666, this, &meta->cDel);
    debugfs_create_atomic_t("vokay", 0666, this, &meta->cVokay);
    debugfs_create_atomic_t("vfail", 0666, this, &meta->cVfail);
}

static int __init talisman_init(void)
{
    dir = debugfs_create_dir("talisman", NULL);
    if (!dir)
        return 0;

    debugfs_create_atomic_t("add", 0666, dir, &stat_add);
    debugfs_create_atomic_t("remove", 0666, dir, &stat_rm);
    debugfs_create_atomic_t("vokay", 0666, dir, &stat_vOkay);
    debugfs_create_atomic_t("vfail", 0666, dir, &stat_vFail);

    /* load endorser specific macros */
    mount_endorser_debugfs(&aa_fname_tbl);
    mount_endorser_debugfs(&exx_task_cred);
    mount_endorser_debugfs(&exx_aa_task_label);

	return 0;
}

static void __exit talisman_exit(void)
{
    if (dir)
        debugfs_remove_recursive(dir);
}

module_init(talisman_init);
module_exit(talisman_exit);

// ********************************************************************************
// *                       Endorser Insertion Functions                           *
// ********************************************************************************

// Record subject data
void endorser_record_subject_data(int key, int value) {
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
        printk(KERN_ERR "Memory allocation failed for subject endorser\n");
        return;
    }
    new_table_entry->key = key;
    new_table_entry->value = value;

    hash_add(subject_hash_table, &new_table_entry->hash_node, key);
}

// Record general object data
void endorser_record_object_data(int key, int value) {
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
	 printk(KERN_ERR "Memory allocation failed for object endorser\n");
	 return;
    }

    new_table_entry->key = key;
    new_table_entry->value = value;
	
    hash_add(object_hash_table, &new_table_entry->hash_node, key);
}


// Record inode object data
void endorser_record_inode_data(int key1, int key2, int value) {
    int constucted_key = key1 * key2;
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = constucted_key;
    new_table_entry->value = value;
	
    hash_add(inode_hash_table, &new_table_entry->hash_node, constucted_key);
}

// Record dentry object data
void endorser_record_dentry_data(int key1, int key2, int value) {
    int constucted_key = key1 * key2;
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = constucted_key;
    new_table_entry->value = value;
	
    hash_add(dentry_hash_table, &new_table_entry->hash_node, constucted_key);
}


// Record file object data
void endorser_record_file_data(int key1, int key2, int value) {
    int constucted_key = key1 * key2;
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = constucted_key;
    new_table_entry->value = value;
	
    hash_add(file_hash_table, &new_table_entry->hash_node, constucted_key);
}

// Record superblock object data
void endorser_record_superblock_data(int key, int value) {
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = key;
    new_table_entry->value = value;
	
    hash_add(superblock_hash_table, &new_table_entry->hash_node, key);
}

// Record ipc object data
void endorser_record_ipc_data(int key, int value) {
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = key;
    new_table_entry->value = value;
	
    hash_add(ipc_hash_table, &new_table_entry->hash_node, key);
}

// Record key object data
void endorser_record_key_data(int key, int value) {
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = key;
    new_table_entry->value = value;
	
    hash_add(key_hash_table, &new_table_entry->hash_node, key);
}

// Record shm object data
void endorser_record_shm_data(int key, int value) {
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = key;
    new_table_entry->value = value;
	
    hash_add(shm_hash_table, &new_table_entry->hash_node, key);
}

// Record sem object data
void endorser_record_sem_data(int key, int value) {
	
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = key;
    new_table_entry->value = value;
	
    hash_add(sem_hash_table, &new_table_entry->hash_node, key);
}

// Record namespace data
void endorser_record_ns_data(char* name_space, int value) {
	
    int constructed_key = xxh64(name_space, sizeof(name_space), value);
    struct endorser_table_entry *new_table_entry = kmalloc(sizeof(struct endorser_table_entry), GFP_KERNEL);
    if (!new_table_entry) {
    	printk(KERN_ERR "Memory allocation failed for object endorser\n");
    	return;
    }
	
    new_table_entry->key = constructed_key;
    new_table_entry->value = value;
	
    hash_add(ns_hash_table, &new_table_entry->hash_node, constructed_key);
}


//********************************************************************************
//*                      Endorser Validation Functions                           *
//********************************************************************************


// Function that checks the value of an object key with a given input
int endorser_validate_object_data(int key, int value) {
    struct endorser_table_entry *data_entry = find_object_data(key);
    
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of an inode key with a given input
int endorser_validate_inode_data(int key1, int key2, int value) {
    int constucted_key = key1 * key2;
	
    struct endorser_table_entry *data_entry = find_inode_data(constucted_key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a dentry key with a given input
int endorser_validate_dentry_data(int key1, int key2, int value) {
    int constucted_key = key1 * key2;
	
    struct endorser_table_entry *data_entry = find_dentry_data(constucted_key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a file key with a given input
int endorser_validate_file_data(int key1, int key2, int value) {
    int constucted_key = key1 * key2;
	
    struct endorser_table_entry *data_entry = find_file_data(constucted_key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a superblock key with a given input
int endorser_validate_superblock_data(int key, int value) {
	
    struct endorser_table_entry *data_entry = find_superblock_data(key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a ipc key with a given input
int endorser_validate_ipc_data(int key, int value) {
	
    struct endorser_table_entry *data_entry = find_ipc_data(key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a linux key's key with a given input
int endorser_validate_key_data(int key, int value) {
	
    struct endorser_table_entry *data_entry = find_key_data(key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a shm key with a given input
int endorser_validate_shm_data(int key, int value) {
	
    struct endorser_table_entry *data_entry = find_shm_data(key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a sem key with a given input
int endorser_validate_sem_data(int key, int value) {
	
    struct endorser_table_entry *data_entry = find_sem_data(key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

// Function that checks the value of a sem key with a given input
int endorser_validate_ns_data(char* name_space, int value) {
	
    int constructed_key = xxh64(name_space, sizeof(name_space), value);
    struct endorser_table_entry *data_entry = find_ns_data(constructed_key);
	
    if (data_entry->value == value) {
    	return 1;
    } else {
    	return 0;
    }
}

//********************************************************************************
//*                             Lookup Functions                                 *
//********************************************************************************

// Function to find data in the subject hash table
struct endorser_table_entry *find_subject_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(subject_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}


// Function to find data in the object hash table
struct endorser_table_entry *find_object_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(object_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the inode hash table
struct endorser_table_entry *find_inode_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(inode_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the dentry hash table
struct endorser_table_entry *find_dentry_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(dentry_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the file hash table
struct endorser_table_entry *find_file_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(file_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the superblock hash table
struct endorser_table_entry *find_superblock_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(superblock_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the ipc hash table
struct endorser_table_entry *find_ipc_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(ipc_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the key hash table
struct endorser_table_entry *find_key_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(key_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the shm hash table
struct endorser_table_entry *find_shm_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(shm_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the sem hash table
struct endorser_table_entry *find_sem_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(sem_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}

// Function to find data in the ns hash table
struct endorser_table_entry *find_ns_data(int key) {
    struct endorser_table_entry *data_entry;
    hash_for_each_possible(ns_hash_table, data_entry, hash_node, key) {
        if (data_entry->key == key) {
            return data_entry;
        }
    }
    return NULL;  // Data not found
}


//********************************************************************************
//*                             Removal Functions                                *
//********************************************************************************

// Function to remove data from the subject hash table
void remove_subject_data(int key) {
    struct endorser_table_entry *data_entry = find_subject_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the object hash table
void remove_object_data(int key) {
    struct endorser_table_entry *data_entry = find_object_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the inode hash table
void remove_inode_data(int key1, int key2) {
    int constructed_key = key1 * key2;
    struct endorser_table_entry *data_entry = find_inode_data(constructed_key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the dentry hash table
void remove_dentry_data(int key1, int key2) {
    int constructed_key = key1 * key2;
    struct endorser_table_entry *data_entry = find_dentry_data(constructed_key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the file hash table
void remove_file_data(int key1, int key2) {
    int constructed_key = key1 * key2;
    struct endorser_table_entry *data_entry = find_file_data(constructed_key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the superblock hash table
void remove_superblock_data(int key) {
    struct endorser_table_entry *data_entry = find_superblock_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the ipc hash table
void remove_ipc_data(int key) {
    struct endorser_table_entry *data_entry = find_ipc_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the key hash table
void remove_key_data(int key) {
    struct endorser_table_entry *data_entry = find_key_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the shm hash table
void remove_shm_data(int key) {
    struct endorser_table_entry *data_entry = find_shm_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the sem hash table
void remove_sem_data(int key) {
    struct endorser_table_entry *data_entry = find_sem_data(key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}

// Function to remove data from the sem hash table
void remove_ns_data(char* name_space, int value) {
    int constructed_key = xxh64(name_space, sizeof(name_space), value);
    struct endorser_table_entry *data_entry = find_ns_data(constructed_key);
    if (data_entry) {
        hash_del(&data_entry->hash_node);
        kfree(data_entry);
    }
}
