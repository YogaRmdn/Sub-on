import time, subprocess as sub
from colorama import Fore as f, Style as s

class Subactive:
	def __init__(self, target, output):
		self.target = target
		self.output = output
	def run(self):
		cmd = sub.run(['httpx', '-l', self.target, '-o', self.output], capture_output=True, text= True)
		result = cmd.stdout
		sub_on = result.splitlines()

		for i, su in enumerate(sorted(sub_on), start=1):
			print(f"{f.GREEN}[{i}]{s.RESET_ALL} {su}")
		print(f"\n{f.GREEN}[+] Found {len(sub_on)} subdomain active{s.RESET_ALL}")
if __name__ == "__main__":
	try:
		print(f"""
 _____     _       _____
|   __|_ _| |_ ___|     |___
|__   | | | . |___|  |  |   |
|_____|___|___|   |_____|_|_|

	{f.RED}github.com/Yogarmdn{s.RESET_ALL}
""")
		target_file = input(f"{f.CYAN}[?]{s.RESET_ALL} File target\t: ")
		output = input(f"{f.CYAN}[?]{s.RESET_ALL} Output file\t: ")
		app = Subactive(target_file, output)
		app.run()
	except KeyboardInterrupt:
		print(f"\n{f.RED}[!] Close your Tools{s.RESET_ALL}")
		time.sleep(0.5)

