
void log_buffer(const char * label, const u_int8_t * buffer, const size_t size, const char * logcat, const int level);
void log_block(const char * label, const u_int64_t * block, const char * logcat, const int level);
void log_state(const char * label, const u_int64_t state[4][5], const char * logcat, const int level);

void validate_init_state(const u_int64_t * P, const u_int64_t * C, const u_int64_t init_block[4][5], const char * logcat);
void validate_generated_input_1(const u_int64_t * P, const u_int64_t init_state[4][5], const char * logcat);
void validate_generated_input_2(const u_int64_t * P1, const u_int64_t * P2, const char * logcat);

