from os import urandom
import time
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes

def sha256_hash(data, log_file):
    digest = hashes.Hash(hashes.SHA256())
    # Start counting the time
    start_time = time.time()
    digest.update(data)
    hash_result = digest.finalize()
    # Stop counting the time
    end_time = time.time()
    hash_time = end_time - start_time

    log_file.write(f"Data: "+str(data.hex())+" | Hash: " + str(hash_result.hex()))
    log_file.write(f"\nTotal hashing time: {hash_time}\n")

    return hash_result, hash_time

def time_hashing(file_sizes, repetitions, log_file):
    hash_times = []

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

        avg_hash_time = total_hash_time / repetitions

        log_file.write(f"\n------------ Ending ------------\n")
        log_file.write(f"Average hashing time: {avg_hash_time}\n")

        hash_times.append(avg_hash_time)

    return hash_times

def plot_results(file_sizes, hashing_times_list, repetitions_list):
    fig, ax = plt.subplots()

    colors = ['blue', 'green', 'red']
    markers = ['o', 's', 'D']

    for i, (hashing_times, repetitions) in enumerate(zip(hashing_times_list, repetitions_list)):
        label_enc = f'Hashing Time ({repetitions} samples)'

        # Convert time values to microseconds
        hashing_times_us = [t * 1e6 for t in hashing_times]

        ax.plot(file_sizes, hashing_times_us, label=label_enc, marker=markers[i], color=colors[i])

    ax.set_xscale('log', base=2)  # Use logarithmic scale for x-axis
    ax.set_xticks(file_sizes)     # Set x-axis ticks to file_sizes

    plt.xlabel('File Size (bytes)')
    plt.ylabel('Time (µs)')
    plt.title('SHA256 Algorithm: Hashing Time vs File Size')
    plt.legend()
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    file_sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]  # bytes
    # Define repetitions for each experiment
    repetitions_list = [5, 10, 15]

    # Log file
    log_file = "sha256.log"

    # Collect hashing times for different repetitions
    hashing_times_list = []
    print("Algorithm: SHA256")
    print("Generating plot and log file...")
    with open(log_file, 'w') as log_file:
        log_file.write("Algorithm: SHA256\n")
        for repetitions in repetitions_list:
            hashing_times = time_hashing(file_sizes, repetitions, log_file)
            hashing_times_list.append(hashing_times)

    # Plot results for all repetitions
    plot_results(file_sizes, hashing_times_list, repetitions_list)

