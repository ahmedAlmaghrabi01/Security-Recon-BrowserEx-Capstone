def filter_qa_lines(file_path):
    count=0
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if '.qa' in line:
                    count += 1
                    print(line.strip(), 'conuter:', count)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    file_path = input("Enter the file path: ")
    filter_qa_lines(file_path)
