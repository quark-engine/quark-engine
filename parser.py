import sys

# TODO just quick but not ideal way to parse the ag file
def parse(filename):
    with open(filename, "r") as f:

        for line in f.readlines():
            if not line.startswith("#"):
                if line.find("]") == -1:
                    if line.find("@") == -1:
                        line_list = line.split(" ")

                        clean = line[19:].lstrip()

                        if len(clean.split()) > 0:
                            yield clean.split()


if __name__ == "__main__":

    if len(sys.argv) == 2:
        for item in parse(sys.argv[1]):
            print(item)

    else:
        print("python3 parser.py filename.ag")
