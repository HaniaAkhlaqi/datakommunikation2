import subprocess

# List of rate arguments to test
rate_arguments = [100000, 200000, 300000,400000, 500000,1000000, 10000000, 50000000, 100000000]

# Output file name
output_file = "simulation_results.txt"

# Open the output file in write mode
with open(output_file, "w") as output:

    # Iterate over rate arguments
    for rate_arg in rate_arguments:
        # Construct the command to execute the script with the current rate argument
        command = [
            "./ns3-run",  # or "python3" depending on your environment
            "task3.py",  # replace with your actual script name
            "--rate={}".format(rate_arg),
        ]

        # Execute the command and capture the output
        result = subprocess.run(command, stdout=subprocess.PIPE, text=True)

        # Write the output to the file
        output.write(f"Simulation with rate={rate_arg} bps:\n")
        output.write(result.stdout)
        output.write("\n" + "=" * 40 + "\n\n")

# Print a message indicating the completion of the simulations
print(f"Simulations completed. Results saved in {output_file}")
