import glob
import statistics

def parse_file(filename: str):
    functions = {}

    with open(filename, "r") as f:
        lines = map(lambda line: line.strip(), f.readlines())
        
    current_function = None
    for line in lines:
        if line[-1] == ":":
            current_function = line[:-1]
            if current_function not in functions:
                functions[current_function] = []
            continue

        functions[current_function] = int(line)

    return functions

def analyse(functions):
    for function in functions:
        print(function)
        print(f"Mean: {statistics.mean(functions[function])}")
        print(f"Median: {statistics.median(functions[function])}")
        print()


for filename in glob.iglob("./results_*"):
    functions = parse_file(filename)
    analyse(functions)
    
