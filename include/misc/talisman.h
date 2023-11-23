/*
 * Talisman: endorsers for LSMs
 */

#ifndef _MISC_TALISMAN_H
#define _MISC_TALISMAN_H

#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/dcache.h>

#define EXX_KEY_TASK(tsk) \
	( (( (__u64)tsk->tgid ) << 32 ) | tsk->pid )
#define EXX_KEY_INODE(inode) \
	( (( (__u64)inode->i_rdev ) << 32) | (inode->i_ino) )


/* Entry types */
enum exx_type {
	EXX_TYPE_INVALID = 0,
	EXX_TYPE_MEMCPY = 1,  // compare by memcpy
	EXX_TYPE_INAME = 2,   // compare by strncmp
};

/* Endorser metadata */
struct exx_meta {
	rwlock_t lck;
	const char *namestr;
	const u8 bits;
	struct hlist_head *tbl;
	enum exx_type type;
	atomic_t cAdd, cDel, cVfail, cVokay;
};

/* Macros to declare  */
#define DEFINE_ENDORSER(name, _bits, _type)               \
        DEFINE_HASHTABLE(__exx_##name, _bits);            \
        struct exx_meta name = {                          \
            __RW_LOCK_UNLOCKED(lck), #name, _bits, __exx_##name, _type,     \
            ATOMIC_INIT(0), ATOMIC_INIT(0), ATOMIC_INIT(0), ATOMIC_INIT(0), \
        };

#define DECLARE_ENDORSER(name)   \
	extern struct exx_meta name;

// Externs declarations of hash tables to refer from LSMs
DECLARE_ENDORSER(exx_task_cred);
DECLARE_ENDORSER(exx_aa_task_label);
DECLARE_ENDORSER(exx_aa_iname);


// Define a structure for key value storage
struct exx_entry {
    __u64 key;
    void *val;
    int val_len;
    struct hlist_node hnode;  // Required for hash table linkage
};

struct exx_entry_iname {
    __u64 key;
    unsigned char iname[DNAME_INLINE_LEN];
    struct hlist_node hnode;  // Required for hash table linkage
};

// Generic hash table functions
void exx_add(struct exx_meta *meta, __u64 key, void *val, int val_len);
int  exx_verify(struct exx_meta *meta, __u64 key, void *val, int val_len);
void exx_rm(struct exx_meta *meta, __u64 key);
void *exx_find(struct exx_meta *meta, __u64 key);
void exx_add_if_absent(struct exx_meta *meta, __u64 key, void *val, int val_len);

// generic type
struct hlist_node *__exx_generic_alloc(struct exx_meta *meta, __u64 key, void *val, int val_len);
struct exx_entry *__exx_generic_find(struct exx_meta *meta, __u64 key);
int __exx_generic_verify(struct exx_meta *meta, __u64 key, void *val, int val_len);
int __exx_generic_rm(struct exx_meta *meta, __u64 key);

// iname type
struct hlist_node *__exx_iname_alloc(struct exx_meta *meta, __u64 key, char *val);
struct exx_entry_iname *__exx_iname_find(struct exx_meta *meta, __u64 key);
int __exx_iname_verify(struct exx_meta *meta, __u64 key, char *val);
int __exx_iname_rm(struct exx_meta *meta, __u64 key);
void inline exx_iname_verify_emulation(char *pathname);

/* duplicate memory to store as value */
void *exx_dup(void *src, size_t len);

#endif /* _MISC_TALISMAN_H */
