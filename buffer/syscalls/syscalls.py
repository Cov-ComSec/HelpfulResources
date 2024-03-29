import requests
from bs4 import BeautifulSoup
from optparse import OptionParser

def makeTable(url):
    """Uses requests to get web page. Then b24 parses the table collecting the records.
    Args:
        - url : The url to use for table generation
    Returns:
        - new_table : a regenerated table with `|` seperators 
    """
    webPage = requests.get(url)
    soup = BeautifulSoup(webPage.text, "html.parser")
    table = soup.find_all('tr')
    new_table = ""

    for i in table:
        record = (i.text).split()
        newrec = "| "
        for col in record:
            newrec += f"{col} | " 
        new_table += newrec + "\n"
    return(new_table)

def writeTable(table, arch):
    """Write table to a txt or custom file
    """
    if options.outFile is not None:
        with open(f"{outFile}", "w") as file:
            file.write(table)
    else:
        with open(f"syscalls_{arch}.txt", "w") as file:
            file.write(table)

if __name__ == "__main__":
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option("-a", "--arch", dest="arch", help="syscall table architecture")
    parser.add_option("-f", "--file", dest="outFile", help="Write to file in format: --file=path/to/file.txt", metavar="FILE")
    (options, args) = parser.parse_args()

    if ("x86"!= options.arch) and ("x64"!= options.arch) and ("arm"!= options.arch) and ("arm64" != options.arch) :
        parser.error("Please enter a valid architecture")
    else:
        pass
    url = f"https://{options.arch.strip()}.syscall.sh/"
    writeTable(makeTable(url), options.arch)
