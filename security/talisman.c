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
/* 2^10 = 1024
 * 2^11 = 2048
 * 2^12 = 4096
 * 2^13 = 8192
 * 2^14 = 16,384
 * 2^15 = 32,768
 * 2^16 = 65,536
 * 2^17 = 131,072
 * 2^18 = 262,144
 * 2^19 = 524,288
 * 2^20 = 1,048,576 */
DEFINE_ENDORSER(exx_task_cred, 13, EXX_TYPE_MEMCPY); // ~6.5k objects (at runtime)
DEFINE_ENDORSER(exx_aa_task_label, 13, EXX_TYPE_MEMCPY); // ~6.5k objects
DEFINE_ENDORSER(exx_aa_iname, 18, EXX_TYPE_INAME); // ~240k objects

DEFINE_ENDORSER(exx_se_task, 13, EXX_TYPE_INT64); // ~6.5k objects
DEFINE_ENDORSER(exx_se_file, 13, EXX_TYPE_MEMCPY); // ? objects
DEFINE_ENDORSER(exx_se_inode, 13, EXX_TYPE_MEMCPY); // ~240k objects

/* Generic hash table functions */

// Add entry to hash table.
// Caller needs to allocate storage for value using kalloc().
// When removing the node kfree() will be called on the value.
void exx_add(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    struct hlist_node *node;

    /* which type? */
    switch (meta->type)
    {
    case EXX_TYPE_MEMCPY:
        node = __exx_generic_alloc(meta, key, val, val_len);
        break;

    case EXX_TYPE_INAME:
        node = __exx_iname_alloc(meta, key, val);
        break;

    case EXX_TYPE_INT64:
        node = __exx_int64_alloc(meta, key, *(__u64 *) val);
        break;

    default:
        printk(KERN_ERR "exx_add: unknown type\n");
        return;
    }

    if (!node) {
        printk(KERN_ERR "exx_add: cannot allocate memory\n");
        return;
    }

    /* add new entry */
    write_lock(&meta->lck);
    hlist_add_head(node, &meta->tbl[hash_min(key, meta->bits)]);
    write_unlock(&meta->lck);

    /* update stats */
    atomic_inc(&meta->cAdd);
    atomic_inc(&stat_add);
    return;
}

// Verify entry in hash table
// Returns: 1 if found, else 0
int exx_verify(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    int ret = 0;

    /* call appropriate function */
    read_lock(&meta->lck);
    switch (meta->type)
    {
    case EXX_TYPE_MEMCPY:
        ret = __exx_generic_verify(meta, key, val, val_len);
        break;

    case EXX_TYPE_INAME:
        ret = __exx_iname_verify(meta, key, val);
        break;

    case EXX_TYPE_INT64:
        ret = __exx_int64_verify(meta, key, *(__u64 *) val);
        break;

    default:
        read_unlock(&meta->lck);
        printk(KERN_ERR "exx_verify: unknown type\n");
        return 0;
    }
    read_unlock(&meta->lck);

    /* update stats */
    if (ret) {
        atomic_inc(&meta->cVokay);
        atomic_inc(&stat_vOkay);
        return 1;
    } else {
        atomic_inc(&meta->cVfail);
        atomic_inc(&stat_vFail);
        return 0;
    }
}

void exx_rm(struct exx_meta *meta, __u64 key) {
    int ret = 0;

    /* remove which type? */
    write_lock(&meta->lck);
    switch (meta->type)
    {
    case EXX_TYPE_MEMCPY:
        ret = __exx_generic_rm(meta, key);
        break;

    case EXX_TYPE_INAME:
        ret = __exx_iname_rm(meta, key);
        break;

    case EXX_TYPE_INT64:
        ret = __exx_int64_rm(meta, key);
        break;

    default:
        printk(KERN_ERR "exx_rm: unknown type\n");
        break;
    }
    write_unlock(&meta->lck);

    /* update stats */
    if (ret) {
        atomic_inc(&meta->cDel);
        atomic_inc(&stat_rm);
    }
}

// return 1 if found; else 0
void *exx_find(struct exx_meta *meta, __u64 key) {
    void *node = NULL;

    /* which type? */
    read_lock(&meta->lck);
    switch (meta->type)
    {
    case EXX_TYPE_MEMCPY:
        node = __exx_generic_find(meta, key);
        break;

    case EXX_TYPE_INAME:
        node = __exx_iname_find(meta, key);
        break;

    case EXX_TYPE_INT64:
        node = __exx_int64_find(meta, key);
        break;

    default:
        read_unlock(&meta->lck);
        printk(KERN_ERR "exx_find: unknown type\n");
        return NULL;
    }
    read_unlock(&meta->lck);
    return node;
}


// NOTE: Only works if we never remove entries.
//       Otherwise, we will have a race condition.
void exx_add_if_absent(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    if (!exx_find(meta, key))
        exx_add(meta, key, val, val_len);
}


///////////////////////////////////////////////////
// generic type
///////////////////////////////////////////////////

struct hlist_node *__exx_generic_alloc(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    struct exx_entry *new;

    new = kmalloc(sizeof(struct exx_entry), GFP_KERNEL);
    if (!new)
        return NULL;
    new->key = key;
    new->val = val;
    new->val_len = val_len;

    return &new->hnode;
}

struct exx_entry *__exx_generic_find(struct exx_meta *meta, __u64 key) {
    struct exx_entry *entry;

    hlist_for_each_entry(entry, &meta->tbl[hash_min(key, meta->bits)], hnode) {
        if (entry->key == key) {
            return entry;
        }
    }
    return NULL;  // Data not found
}

int __exx_generic_verify(struct exx_meta *meta, __u64 key, void *val, int val_len) {
    struct exx_entry *ent = __exx_generic_find(meta, key);
    if (!ent)
        return 0;

    /* compare result */
    if ((ent->val_len == val_len) && memcmp(ent->val, val, val_len))
        return 1;

    return 0;
}

/* 1 on success; 0 on fail */
int __exx_generic_rm(struct exx_meta *meta, __u64 key) {
    struct exx_entry *entry = __exx_generic_find(meta, key);
    if (entry) {
        hash_del(&entry->hnode);
        kfree(entry->val);
        kfree(entry);
        return 1;
    }
    return 0;
}


///////////////////////////////////////////////////
// iname type
///////////////////////////////////////////////////

struct hlist_node *__exx_iname_alloc(struct exx_meta *meta, __u64 key, char *val) {
    struct exx_entry_iname *new;

    new = kmalloc(sizeof(struct exx_entry_iname), GFP_KERNEL);
    if (!new)
        return NULL;
    new->key = key;
    strncpy(new->iname, val, sizeof(new->iname));
    new->iname[sizeof(new->iname)-1] = '\0';

    return &new->hnode;
}

struct exx_entry_iname *__exx_iname_find(struct exx_meta *meta, __u64 key) {
    struct exx_entry_iname *entry;

    hlist_for_each_entry(entry, &meta->tbl[hash_min(key, meta->bits)], hnode) {
        if (entry->key == key) {
            return entry;
        }
    }
    return NULL;  // Data not found
}

int __exx_iname_verify(struct exx_meta *meta, __u64 key, char *val) {
    struct exx_entry_iname *ent = __exx_iname_find(meta, key);
    if (!ent)
        return 0;

    /* compare result */
    if (strncmp(ent->iname, val, sizeof(ent->iname)) == 0)
        return 1;

    return 0;
}

/* 1 on success; 0 on fail */
int __exx_iname_rm(struct exx_meta *meta, __u64 key) {
    struct exx_entry_iname *entry = __exx_iname_find(meta, key);
    if (entry) {
        hash_del(&entry->hnode);
        kfree(entry);
        return 1;
    }
    return 0;
}


#pragma GCC push_options
#pragma GCC optimize ("O0")
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"

void inline exx_iname_verify_emulation(char *pathname) {
	if (pathname)
		strlen(pathname);
}

#pragma GCC diagnostic pop
#pragma GCC pop_options


///////////////////////////////////////////////////
// int64 type
///////////////////////////////////////////////////

struct hlist_node *__exx_int64_alloc(struct exx_meta *meta, __u64 key, __u64 val) {
    struct exx_entry_int64 *new;

    new = kmalloc(sizeof(struct exx_entry_int64), GFP_KERNEL);
    if (!new)
        return NULL;
    new->key = key;
    new->val = val;

    return &new->hnode;
}

struct exx_entry_int64 *__exx_int64_find(struct exx_meta *meta, __u64 key) {
    struct exx_entry_int64 *entry;

    hlist_for_each_entry(entry, &meta->tbl[hash_min(key, meta->bits)], hnode) {
        if (entry->key == key) {
            return entry;
        }
    }
    return NULL;  // Data not found
}

int __exx_int64_verify(struct exx_meta *meta, __u64 key, __u64 val) {
    struct exx_entry_int64 *ent = __exx_int64_find(meta, key);
    if (!ent)
        return 0;

    /* compare result */
    if (val == ent->val)
        return 1;

    return 0;
}

/* 1 on success; 0 on fail */
int __exx_int64_rm(struct exx_meta *meta, __u64 key) {
    struct exx_entry_int64 *entry = __exx_int64_find(meta, key);
    if (entry) {
        hash_del(&entry->hnode);
        kfree(entry);
        return 1;
    }
    return 0;
}


///////////////////////////////////////////////////
// Misc.
///////////////////////////////////////////////////

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
    mount_endorser_debugfs(&exx_task_cred);
    mount_endorser_debugfs(&exx_aa_task_label);
    mount_endorser_debugfs(&exx_aa_iname);

    mount_endorser_debugfs(&exx_se_task);
    mount_endorser_debugfs(&exx_se_file);
    mount_endorser_debugfs(&exx_se_inode);

	return 0;
}

static void __exit talisman_exit(void)
{
    if (dir)
        debugfs_remove_recursive(dir);
}

module_init(talisman_init);
module_exit(talisman_exit);
