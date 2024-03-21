from os import urandom
import time
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes

def sha256_hash(data, log_file):
    digest = hashes.Hash(hashes.SHA256())
    start_time = time.time()
    digest.update(data)
    hash_result = digest.finalize()
    end_time = time.time()
    hash_time = end_time - start_time
    return hash_result, hash_time

def hashing_random(file_sizes, repetitions, log_file):
    hash_times = []

    print("------------ Random Files Test ------------\n")


    log_file.write(f"------------ Number of samples: {repetitions} ------------\n")

    for size in file_sizes:
        total_hash_time = 0

        log_file.write(f"\n------------ Starting ------------\n")
        log_file.write(f"File size: {size} bytes\n")

        for i in range(repetitions):
            data = urandom(size)

            log_file.write(f"\nFile: {i}\n")

            hash_result, hash_time = sha256_hash(data, log_file=log_file)
            total_hash_time += hash_time

            log_file.write(f"Data: {str(data.hex())} \n")
            log_file.write(f"Hash: {str(hash_result.hex())} \n")
            log_file.write(f"Total hashing time: {hash_time}\n")


        avg_hash_time = total_hash_time / repetitions

        log_file.write(f"\n------------ Ending ------------\n")
        log_file.write(f"Average hashing time: {avg_hash_time}\n")

        hash_times.append(avg_hash_time)

        print(f"File size: {size} | Average hashing time: {avg_hash_time}\n")


    return hash_times

def hashing_same(file_sizes, repetitions, log_file):
    hash_times = []

    print("------------ Same Files Test ------------\n")


    log_file.write(f"------------ Number of samples: {repetitions} ------------\n")

    for size in file_sizes:
        total_hash_time = 0

        log_file.write(f"\n------------ Starting ------------\n")
        log_file.write(f"File size: {size} bytes\n")

        data = urandom(size)
        for i in range(repetitions):

            log_file.write(f"\nFile: {i}\n")

            hash_result, hash_time = sha256_hash(data, log_file=log_file)
            total_hash_time += hash_time

            log_file.write(f"Data: {str(data.hex())} \n")
            log_file.write(f"Hash: {str(hash_result.hex())} \n")
            log_file.write(f"Total hashing time: {hash_time}\n")


        avg_hash_time = total_hash_time / repetitions

        log_file.write(f"\n------------ Ending ------------\n")
        log_file.write(f"Average hashing time: {avg_hash_time}\n")

        hash_times.append(avg_hash_time)
    
        print(f"File size: {size} | Average hashing time: {avg_hash_time}\n")


    return hash_times

def plot_results(file_sizes, hashing_time, hashing_time_same, repetitions):
    fig, ax = plt.subplots()
    
    colors = ['blue', 'red']
    markers = ['o', 's']
    
    # Plot random files encryption and decryption
    ax.plot(file_sizes, [t * 1e6 for t in hashing_time], label='Random Files hashing', marker=markers[0], color=colors[0])
    # Plot same file encryption and decryption
    ax.plot(file_sizes, [t * 1e6 for t in hashing_time_same], label='Same File hashing', marker=markers[1], color=colors[1])

    ax.set_xscale('log', base=2)  
    ax.set_xticks(file_sizes)     
    
    plt.xlabel('File Size (bytes)')
    plt.ylabel('Time (µs)')
    plt.title(f'SHA256 Algorithm: Hashing Time vs File Size ({repetitions} samples)')
    plt.legend()
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    file_sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]  # bytes
    # Define repetitions for each experiment
    repetitions = 1000

    # Log file
    log_file = "sha256.log"
    log_file_same = "sha256_same.log"

    print("Algorithm: SHA256")
    print("Generating plot and log file...")
    print("\n-------------------------------------\n")


    with open(log_file, 'w') as log_file:
        log_file.write("Algorithm: SHA256\n")
        hashing_times = hashing_random(file_sizes, repetitions, log_file)

    with open(log_file_same, 'w') as log_file:
        log_file.write("Algorithm: SHA256\n")
        hashing_times_same = hashing_same(file_sizes, repetitions, log_file)

    # Plot results for all repetitions
    plot_results(file_sizes, hashing_times, hashing_times_same, repetitions)

