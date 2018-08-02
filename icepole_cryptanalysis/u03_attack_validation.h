
//void validate_init_state(const u_int64_t * P, const u_int64_t * C, const u_int64_t init_state[4][5], const char * logcat);
void validate_generated_input_1(const size_t thd_id, const u_int64_t * P, const u_int64_t init_state[4][5], const char * logcat);
void validate_generated_input_2(const size_t thd_id, const u_int64_t * P1, const u_int64_t * P2, const char * logcat);
void validate_state_bits(const size_t thd_id, const u_int64_t x_state[4][5], const u_int8_t F, const char * logcat);
void validate_counter_bits(const size_t thd_id, const u_int64_t * C, const size_t n, const char * logcat);
