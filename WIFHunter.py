import secp256k1 as ice
import datetime
import os
import random
import subprocess

# === Path Setup ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")

# === Make sure reports folder exists ===
if not os.path.exists(REPORTS_FOLDER):
    os.makedirs(REPORTS_FOLDER)

def log(message_):
    message_ = "[{}] {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message_)
    print(message_)
    with open(LOG_FILE, "a") as file:
        file.write(message_ + "\n")

def save_found_key(hex_key, dec_key, h160c, h160u):
    with open(FOUND_KEY_FILE, "w") as file:
        file.write(f"Found matching private key!\n")
        file.write(f"Compressed HASH160: {h160c}\n")
        file.write(f"Uncompressed HASH160: {h160u}\n")
        file.write(f"Private key (hex): {hex_key}\n")
        file.write(f"Private key (decimal): {dec_key}\n")
    log(f"[I] Private key saved to {FOUND_KEY_FILE}")

# === Main Script ===
try:
    while True:
        # Generate valid unused prefix
        while True:
            prefix = random.choice(["K", "L"]) + "".join(random.sample("zyxwvutsrqponmkjihgfedcbaZYXWVUTSRQPNMLKJHGFEDCBA987654321", 5))
            report_path = os.path.join(REPORTS_FOLDER, f"{prefix}.txt")
            if "KxFyGD" <= prefix < "L5oLmv" and not os.path.exists(report_path):
                break

        # Update file paths now that prefix is known
        LOG_FILE = report_path
        FOUND_KEY_FILE = os.path.join(REPORTS_FOLDER, "found_key.txt")

        log(f"[I] Starting scan for prefix: {prefix}")

        prefix = "KwDiBf" # To Test Prefix for Puzzle 1 (put # for WIF 500)
        #Puzzle 1# const char WIF_ENDING[] = "jEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        #Puzzle 1# target_h160 = "751e76e8199196d454941c45d1b3a323f1433bd6"
        # WIF500 # const char WIF_ENDING[] = "5bCRZhiS5sEGMpmcRZdpAhmWLRfMmutGmPHtjVob";
        # WIF500 # target_h160 = "f894ae393519664b55749b372f53d61f42253e13"
        process = subprocess.Popen(["./WIFHunter", prefix], stdout=subprocess.PIPE)
        line = process.stdout.readline()
        found = False

        while len(line) > 0:
            line = line.decode().strip()
            log(line)
            message_type = line[:4]
            message = line[4:]

            if message_type == "[W] ":
                HEX = ice.btc_wif_to_pvk_hex(message)
                dec = int(HEX, 16)
                h160c = ice.privatekey_to_h160(0, True, dec).hex()
                h160u = ice.privatekey_to_h160(0, False, dec).hex()
                target_h160 = "751e76e8199196d454941c45d1b3a323f1433bd6" #Puzzle 1

                if h160c == target_h160 or h160u == target_h160:
                    print("Found matching private key!")
                    log("[i] PRIVATE KEY FOUND!!!")
                    log(f"Compressed HASH160: {h160c}")
                    log(f"Uncompressed HASH160: {h160u}")
                    log(f"Private key (hex): {HEX}")
                    log(f"Private key (decimal): {dec}")

                    save_found_key(HEX, dec, h160c, h160u)

                    process.terminate()
                    found = True
                    break

            elif message_type == "[E] ":
                log(line)

            line = process.stdout.readline()

        if found:
            break

        process.wait()

        if process.returncode != 0:
            log(f"[E] Wrong return code: {process.returncode}")

except KeyboardInterrupt:
    log("[i] Script stopped by user")

except Exception as e:
    log(f"[E] Unexpected error: {str(e)}")

finally:
    log("[i] Script execution ended")
