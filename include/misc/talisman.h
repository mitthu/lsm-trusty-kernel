/*
 * Talisman: endorsers for LSMs
 */

#ifndef _MISC_TALISMAN_H
#define _MISC_TALISMAN_H

#include <linux/hashtable.h>
#include <linux/types.h>

#define EXX_TBL_BITS 8
#define EXX_KEY_TASK(tsk) \
	( (( (__u64)tsk->tgid ) << 32 ) | tsk->pid )
#define EXX_KEY_INODE(inode) \
	( (( (__u64)inode->i_rdev ) << 32) | (inode->i_ino) )

#define DEFINE_HASHTABLE_EXTERN(name, bits) \
    extern struct hlist_head name[];

// Externs declarations of hash tables to refer from LSMs
DEFINE_HASHTABLE_EXTERN(aa_fname_tbl, EXX_TBL_BITS);
DEFINE_HASHTABLE_EXTERN(task_tbl, EXX_TBL_BITS);

//********************************************************************************
//*                       Endorser Function Declarations                         *
//********************************************************************************


/*

	- Place header file in appropriate location for compilation
		- include directory
		- top level root directory
		- custom location where path is specified manually at compile time
	- Add "#include <endorser.h>" to any source code files that require endorsement
	- Leverage API calls from header file to endorse supported data types


	Subjects:
		current
	Objects:
		inode
		dentry
		file
		superblock
		ipc
		key
		shared memory
		semaphore	
*/

// Define a structure for key value storage
struct endorser_table_entry {
    int key;
    int value;
    struct hlist_node hash_node;  // Required for hash table linkage
};

struct exx_entry {
    __u64 key;
    void *val;
    int val_len;
    struct hlist_node hnode;  // Required for hash table linkage
};

// Generic hash table functions
void exx_add(struct hlist_head *tbl, __u64 key, void *val, int val_len);
int  exx_verify(struct hlist_head *tbl, __u64 key, void *val, int val_len);
struct exx_entry *exx_find(struct hlist_head *tbl, __u64 key);
void exx_rm(struct hlist_head *tbl, __u64 key);

/* duplicate memory to store as value */
void *exx_dup(void *src, size_t len);

// // Function declarations for aa_object hashing and retrieval
// void enx_aa_fname_add(int value);
// int  exx_aa_fname_verify(pid_t key, int value);
// struct endorser_table_entry *exx_aa_fname_get(pid_t key);
// void exx_aa_fname_rm(int key);


// Function declarations for subject hashing and retrieval
void endorser_record_subject_data(int key, int value);
int endorser_validate_subject_data(int key, int value);
struct endorser_table_entry *find_subject_data(int key);
void remove_subject_data(int key);


// Function declarations for general object hashing and retrieval
void endorser_record_object_data(int key, int value);
int endorser_validate_object_data(int key, int value);
struct endorser_table_entry *find_object_data(int key);
void remove_object_data(int key);

// Function declarations for inode hashing and retrieval
void endorser_record_inode_data(int key1, int key2, int value);
int endorser_validate_inode_data(int key1, int key2, int value);
struct endorser_table_entry *find_inode_data(int key);
void remove_inode_data(int key1, int key2);

// Function declarations for dentry hashing and retrieval
void endorser_record_dentry_data(int key1, int key2, int value);
int endorser_validate_dentry_data(int key1, int key2, int value);
struct endorser_table_entry *find_dentry_data(int key);
void remove_dentry_data(int key1, int key2);

// Function declarations for file hashing and retrieval
void endorser_record_file_data(int key1, int key2, int value);
int endorser_validate_file_data(int key1, int key2, int value);
struct endorser_table_entry *find_file_data(int key);
void remove_file_data(int key1, int key2);

// Function declarations for superblock hashing and retrieval
void endorser_record_superblock_data(int key, int value);
int endorser_validate_superblock_data(int key, int value);
struct endorser_table_entry *find_superblock_data(int key);
void remove_superblock_data(int key);

// Function declarations for ipc hashing and retrieval
void endorser_record_ipc_data(int key, int value);
int endorser_validate_ipc_data(int key, int value);
struct endorser_table_entry *find_ipc_data(int key);
void remove_ipc_data(int key);

// Function declarations for key hashing and retrieval
void endorser_record_key_data(int key, int value);
int endorser_validate_key_data(int key, int value);
struct endorser_table_entry *find_key_data(int key);
void remove_key_data(int key);

// Function declarations for shared memory hashing and retrieval
void endorser_record_shm_data(int key, int value);
int endorser_validate_shm_data(int key, int value);
struct endorser_table_entry *find_shm_data(int key);
void remove_shm_data(int key);

// Function declarations for semaphore hashing and retrieval
void endorser_record_sem_data(int key, int value);
int endorser_validate_sem_data(int key, int value);
struct endorser_table_entry *find_sem_data(int key);
void remove_sem_data(int key);

// Function declarations for namespace hashing and retrieval
void endorser_record_ns_data(char* name_space, int value);
int endorser_validate_ns_data(char* name_space, int value);
struct endorser_table_entry *find_ns_data(int key);
void remove_ns_data(char* name_space, int value);

#endif /* _MISC_TALISMAN_H */
