//__PJ_ENCLAVE_H_


typedef struct pj_enclave {

	void (*ptr_encoder)(char *decMessageIn, size_t lenIn, char *encMessageOut, size_t &lenOut);
	void (*ptr_decoder)(char *encMessageIn, size_t lenIn, char *decMessageOut, size_t &lenOut);

	struct{
	
		uint64_t global_eid;

		char codec_name[16];

	}param;

}pj_enclave;

//__PJ_ENCLAVE_H_
