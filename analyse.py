import glob
import statistics
import re

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

        functions[current_function].append(int(re.sub("[^0-9]", "", line)))

    return functions

def analyse(functions):
    for function in functions:
        print(f"{function}:")
        print(f"Mean: {round(statistics.mean(functions[function]))}")
        print(f"Median: {round(statistics.median(functions[function]))}")
        print()


for filename in glob.iglob("./results_*"):
    functions = parse_file(filename)
    print(filename)
    analyse(functions)
