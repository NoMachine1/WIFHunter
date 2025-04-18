#include <iostream>
#include <mutex>
#include <thread>
#include <immintrin.h>
#include <cstring>
#include <chrono>
#include <ctime>
#include "sha256_avx2.h"

using namespace std;

#define PREFIX_LENGTH 6
#define ROOT_LENGTH 6

const char WIF_ENDING[] = "jEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

char* prefix;
mutex mutex_;
int threads_number;
int* threads_progresses;
int progresses_number;


// Timer class definition
class Timer {
private:
    unsigned long long timer;
    unsigned long long time() {
        return chrono::duration_cast<chrono::milliseconds>(
            chrono::system_clock::now().time_since_epoch()).count();
    }
public:
    Timer() { timer = time(); }
    unsigned long long stop(int iterations) {
        unsigned long long newTime = time();
        unsigned long long returnTime = (newTime - timer) * (1000000000 / iterations) / 1000;
        timer = newTime;
        return returnTime;
    }
    double stop() {
        unsigned long long newTime = time();
        double returnTime = (double)(newTime - timer) / 1000;
        timer = newTime;
        return returnTime;
    }
};

// Global timer instance
Timer timer;

bool check(const unsigned char* array1, const unsigned char* array2, int length) {
    for (int c = 0; c < length; c++)
        if (array1[c] != array2[c])
            return false;
    return true;
}


    // Constants with optimal alignment
    alignas(64) const char BASE58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    alignas(64) const unsigned char BASE58_MAP[256] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0xFF, 0x11, 0x12, 0x13, 0x14, 0x15, 0xFF,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0xFF, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

typedef __uint128_t uint128_t;

void decode(const unsigned char* input, unsigned char* output) {
    alignas(64) uint64_t digits[52] = {0};
    int digitslen = 1;
    const int length = strlen((const char*)input);

    // Unroll the first loop iteration to avoid zero multiplication
    if (length > 0) {
        uint64_t current_char = BASE58_MAP[input[0]];
        digits[0] = current_char;
    }

    for (int i = 1; i < length; ++i) {
        uint64_t current_char = BASE58_MAP[input[i]];
        uint128_t carry = current_char;

        // Process digits with 128-bit arithmetic
        int j = 0;
        for (; j + 3 < digitslen; j += 4) {
            // Small loop unrolling (4 iterations)
            uint128_t product0 = ((uint128_t)digits[j] * 58) + carry;
            digits[j] = (uint64_t)(product0 & 0xFFFFFFFFFFFFFFFF);
            carry = product0 >> 64;

            uint128_t product1 = ((uint128_t)digits[j+1] * 58) + carry;
            digits[j+1] = (uint64_t)(product1 & 0xFFFFFFFFFFFFFFFF);
            carry = product1 >> 64;

            uint128_t product2 = ((uint128_t)digits[j+2] * 58) + carry;
            digits[j+2] = (uint64_t)(product2 & 0xFFFFFFFFFFFFFFFF);
            carry = product2 >> 64;

            uint128_t product3 = ((uint128_t)digits[j+3] * 58) + carry;
            digits[j+3] = (uint64_t)(product3 & 0xFFFFFFFFFFFFFFFF);
            carry = product3 >> 64;
        }

        // Process remaining digits
        for (; j < digitslen; j++) {
            uint128_t product = ((uint128_t)digits[j] * 58) + carry;
            digits[j] = (uint64_t)(product & 0xFFFFFFFFFFFFFFFF);
            carry = product >> 64;
        }

        // Store remaining carry
        while (carry > 0 && digitslen < 52) {
            digits[digitslen++] = (uint64_t)(carry & 0xFFFFFFFFFFFFFFFF);
            carry >>= 64;
        }
    }

    // Convert to big-endian byte array
    int out_pos = 0;
    bool leading_zero = true;

    for (int i = digitslen - 1; i >= 0; i--) {
        uint64_t digit = digits[i];

        // Use __builtin_bswap64 to reverse the byte order of the 64-bit integer
        uint64_t swapped_digit = __builtin_bswap64(digit);

        // Process each byte of the swapped 64-bit digit
        uint8_t* bytes = (uint8_t*)&swapped_digit;

        // Skip leading zeros only once
        if (leading_zero) {
            int k = 0;
            while (k < 8 && bytes[k] == 0) k++;
            if (k < 8) {
                leading_zero = false;
                memcpy(output + out_pos, bytes + k, 8 - k);
                out_pos += 8 - k;
            }
        } else {
            memcpy(output + out_pos, bytes, 8);
            out_pos += 8;
        }
    }

    // Pad with zeros if necessary
    if (out_pos < 38) {
        memset(output + out_pos, 0, 38 - out_pos);
    }
}

struct alignas(64) WIFBatch {
    unsigned char wifs[8][52 + 1];
    unsigned char extended_keys[8][64];
};


void init_batch(WIFBatch& batch, int i0, int i1, int i2, int i3, int i4, int i5_base, int batch_size) {
    const size_t ending_length = strlen(WIF_ENDING);

    for (int b = 0; b < batch_size; ++b) {
        int i5 = i5_base + b;
        memcpy(batch.wifs[b], prefix, PREFIX_LENGTH);
        batch.wifs[b][PREFIX_LENGTH]     = BASE58[i0];
        batch.wifs[b][PREFIX_LENGTH + 1] = BASE58[i1];
        batch.wifs[b][PREFIX_LENGTH + 2] = BASE58[i2];
        batch.wifs[b][PREFIX_LENGTH + 3] = BASE58[i3];
        batch.wifs[b][PREFIX_LENGTH + 4] = BASE58[i4];
        batch.wifs[b][PREFIX_LENGTH + 5] = BASE58[i5];

        memcpy(batch.wifs[b] + PREFIX_LENGTH + ROOT_LENGTH, WIF_ENDING, ending_length + 1);

        // Initialize extended_keys with known pattern
        memset(batch.extended_keys[b], 0, 64);
        batch.extended_keys[b][0] = 0x80;
        batch.extended_keys[b][33] = 0x01;
    }
}

void process_batch(WIFBatch& batch, int batch_size) {
    alignas(64) unsigned char payloads[8][34];
    alignas(64) unsigned char stored_checksums[8][4];
    alignas(64) unsigned char avx_inputs[8][64] = {0};
    bool valid_candidate[8] = {false};

    // Decode all WIFs in the batch
    for (int i = 0; i < batch_size; ++i) {
        decode(batch.wifs[i], batch.extended_keys[i]);
    }

    // Decode and validate candidates
    for (int i = 0; i < batch_size; ++i) {
        if (batch.extended_keys[i][0] == 0x80 && batch.extended_keys[i][33] == 0x01) {
            memcpy(payloads[i], batch.extended_keys[i], 34);
            memcpy(stored_checksums[i], batch.extended_keys[i] + 34, 4);
            valid_candidate[i] = true;

            // Prepare AVX inputs while we have the payload
            memcpy(avx_inputs[i], payloads[i], 34);
	    avx_inputs[i][0]   = 0x80;
	    avx_inputs[i][33] = 0x01;
	    avx_inputs[i][34] = 0x80;
	    avx_inputs[i][62] = 0x01;
	    avx_inputs[i][63] = 0x10;
        }
    }

    // Process all valid candidates with AVX2
    alignas(64) unsigned char digest1[8][32];
    sha256avx2_8B(
        avx_inputs[0], avx_inputs[1], avx_inputs[2], avx_inputs[3],
        avx_inputs[4], avx_inputs[5], avx_inputs[6], avx_inputs[7],
        digest1[0], digest1[1], digest1[2], digest1[3],
        digest1[4], digest1[5], digest1[6], digest1[7]
    );

    // Prepare second round inputs
    alignas(64) unsigned char second_inputs[8][64] = {0};
    for (int i = 0; i < batch_size; ++i) {
        if (valid_candidate[i]) {
            memcpy(second_inputs[i], digest1[i], 32);
            second_inputs[i][32] = 0x80;
            second_inputs[i][63] = 0x00;
            second_inputs[i][62] = 0x01;
        }
    }

    // Second SHA-256 round
    alignas(64) unsigned char digest2[8][32];
    sha256avx2_8B(
        second_inputs[0], second_inputs[1], second_inputs[2], second_inputs[3],
        second_inputs[4], second_inputs[5], second_inputs[6], second_inputs[7],
        digest2[0], digest2[1], digest2[2], digest2[3],
        digest2[4], digest2[5], digest2[6], digest2[7]
    );

    // Check results and output valid WIFs
    for (int i = 0; i < batch_size; ++i) {
        if (valid_candidate[i] && memcmp(stored_checksums[i], digest2[i], 4) == 0) {
            lock_guard<mutex> lock(mutex_);
            cout <<  "\r[W] " << batch.wifs[i] << "\r" << endl;
            cout << "\r";
        }
    }
}

void thread_function(int thread_id) {
    WIFBatch batch;
    int to = (thread_id + 1) * 58 / threads_number;
    
    for (int i0 = thread_id * 58 / threads_number; i0 < to; i0++) {
        for (int i1 = 0; i1 < 58; i1++) {
            for (int i2 = 0; i2 < 58; i2++) {
                for (int i3 = 0; i3 < 58; i3++) {
                    for (int i4 = 0; i4 < 58; i4++) {
                        // Process in batches of 8 for full AVX2 utilization
                        for (int i5_base = 0; i5_base < 58; i5_base += 8) {
                            int batch_size = min(8, 58 - i5_base);
                            init_batch(batch, i0, i1, i2, i3, i4, i5_base, batch_size);
                            process_batch(batch, batch_size);
                        }
                    }
                }
            }
            
            lock_guard<mutex> lock(mutex_);
            threads_progresses[thread_id]++;
            bool log = true;
            for (int j = 0; j < threads_number; j++) {
                if (threads_progresses[j] < threads_progresses[thread_id]) {
                    log = false;
                    break;
                }
            }
            if (log) {
                double progress = threads_progresses[thread_id] * 100.0L / progresses_number;
                double speed = (threads_number * 58 * 58 * 58 * 58) / timer.stop() / 1e6;
                cout << "\r[I] Progress = " << fixed << progress 
                << " % [" << fixed << speed << " Mkeys/sec]" << "\r" << endl; 
            }
        }
    }
    
    lock_guard<mutex> lock(mutex_);
    threads_progresses[thread_id] = progresses_number;
}

int main(int argc, char* argv[]) {
    cout << "\r[I] WIF Hunter" << "\r" << endl;
    cout.precision(2);

    if (argc < 2) {
        cout << "[E] No parameter with WIF prefix" << endl;
        return 0;
    }
    if (strlen(argv[1]) != PREFIX_LENGTH) {
        cout << "\r[E] Wrong length of WIF prefix: " << strlen(argv[1]) << endl;
        return 0;
    }

    prefix = argv[1];
    for (int i = 0; i < PREFIX_LENGTH; i++) {
        if (!strchr(BASE58, prefix[i])) {
            cout << "\r[E] Wrong symbol of WIF prefix: " << prefix[i] << endl;
            return 0;
        }
    }

    cout << "\r[I] CHECKING WIF PREFIX " << prefix << ":" << endl;

    threads_number = thread::hardware_concurrency();
    if (!threads_number) threads_number = 1;
    
    thread* threads = new thread[threads_number];
    threads_progresses = new int[threads_number]{0};
    progresses_number = (58 / threads_number + (58 % threads_number ? 1 : 0)) * 58;
    timer = Timer();

    for (int t = 0; t < threads_number; t++) {
        threads[t] = thread(thread_function, t);
    }

    for (int t = 0; t < threads_number; t++) {
        threads[t].join();
    }

    delete[] threads;
    delete[] threads_progresses;
    cout << "\r[I] WIF PREFIX " << prefix << " CHECKED" << endl;
    return 0;
}
