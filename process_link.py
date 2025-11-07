import sys

def analyze_link(link):
    # Replace with real logic
    return f"Link '{link}' analyzed successfully!"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No link provided")
        sys.exit(1)
    
    link = sys.argv[1]
    result = analyze_link(link)
    print(result)
    print("blah blah blah")
