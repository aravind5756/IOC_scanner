LOG_FILE = "sample.log"


def main():
    with open(LOG_FILE, "r") as f:
        for line in f:
            print(line.rstrip())


if __name__ == "__main__":
    main()
