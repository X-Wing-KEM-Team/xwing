import glob
import statistics
import json

algorithms = {}


def parse_file(filename: str):
    functions = {}

    with open(filename, "r") as f:
        lines = map(lambda line: line.strip(), f.readlines())

    current_function = None
    for line in lines:
        if len(line) == 0:
            continue
        if line[-1] == ":":
            current_function = line[:-1]
            if current_function not in functions:
                functions[current_function] = []
            continue

        functions[current_function].append(int(line))
    return functions


def analyse(filename, functions):
    for function in functions:
        print(f"{function}:")
        print(f"Mean: {round(statistics.mean(functions[function]))}")
        print(f"Median: {round(statistics.median(functions[function]))}")
        print()
        if filename.replace("./results_", "") not in algorithms:
            algorithms[filename.replace("./results_", "")] = {}
        algorithms[filename.replace("./results_", "")][
            function.replace("xkem_", "").replace("gkem_", "")
        ] = round(statistics.mean(functions[function]))


for filename in glob.iglob("./results_*"):
    functions = parse_file(filename)
    print(filename)
    analyse(filename, functions)

with open("test_speed_results.json", "w") as write_file:
    json.dump(algorithms, write_file, indent=2)
