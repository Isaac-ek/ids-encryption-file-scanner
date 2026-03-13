from colorama import Fore, Style


def info(msg: str) -> None:
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")


def warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")


def error(msg: str) -> None:
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
