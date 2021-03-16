#!/usr/bin/env python3
# Password analysis tool
# https://github.com/sc1341

import matplotlib.pyplot as plt
import collections, statistics, argparse, re


def load_passwords(file: str, sep: str):
	"""
	Returns a list of passwords from a file
	"""
	passwords = []
	for cred in open(file, "r"):
		cred = cred.strip("\n")
		# Check to make sure sep exists so it doesn't split at the nothingth char
		if sep != '':
			cred = cred.split(sep)
			passwords.append(cred[1])
		else:
			passwords.append(cred)
	return passwords


def in_list(creds:list, word_list: str):
	"""
	Determines what passwords are found in the wordlist file, and the 
	number of occurences. 

	This feature really isn't great. Takes absolute ages with rockyou.txt
	"""
	rockyou = []
	for word in creds:
		for word2 in open(word_list):
			if word == word2.strip("\n"):
				rockyou.append(word)
	return collections.Counter(rockyou)


def in_list_graph(creds: dict, wordlist_name:str, title:str):
	"""
	Creates a bar graph of what password and how many times is it used in a wordlist
	"""
	data = {x[0]:x[1] for x in c.most_common(10)} 
	b = plt.bar(data.keys(), data.values())
	plt.xlabel("Password")
	plt.ylabel("Number of occurences")
	plt.title(f"{title}\nTop 10 common passwords found in {wordlist_name}")
	plt.show()

def most_common_passwords(creds: list, num: int):
	"""
	Returns the top num most common passwords
	"""
	return collections.Counter(creds).most_common(num)

def most_common_passwords_graph(creds: list, num: int):
	"""
	Creates a graph from the most common passwords
	"""
	c = collections.Counter(creds)
	data = {x[0]:x[1] for x in c.most_common(num)} 
	# I am not sure this really makes a difference or not with spacing... will check back on this
	b = plt.bar(['   ' + x + '   ' for x in data.keys()], data.values(), align='center')
	plt.title(f"Top {num} most common passwords")
	plt.xlabel("Password")
	plt.ylabel("Number of occurances")
	plt.show()

def get_password_lengths(creds: list):
	"""
	Determine how many passwords have what lengths
	"""
	lengths = {}
	s = 0
	for p in creds:
		if len(p) not in lengths.keys():
			lengths[len(p)] = 1
		else:
			lengths[len(p)] += 1
		s += len(p)
	
	# The reason I didn't make this an orderdict or use Collections.Counter is I wanted a direct way to
	# find the average and median lengths
	data = {"average_length": s/len(creds), "median_length": statistics.median([len(x) for x in creds]), "lengths":lengths}
	return data

def graph_password_lengths(lengths: dict, show_median: bool, title:str):
	"""
	Creates and displays a bar graph showing password lengths and number of occurences. 
	"""
	od = collections.OrderedDict(sorted(lengths['lengths'].items()))
	b = plt.bar(od.keys(), od.values())
	# Get start to end for graph ranges. Cannot use indexing on OD object :-(
	start, *_, end = od.keys()
	plt.xticks([x for x in range(start, end+1)])
	plt.xlabel("Password length")
	plt.ylabel("Number of passwords")
	if show_median == True:
		plt.title(f"{title}\nTotal passwords cracked: {sum(lengths['lengths'].values())}\nMedian password length: {lengths['median_length']}")
	plt.show()

def pattern_detection(creds: list):
	patterns = {
	"Capitalized":"^[A-Z].*",
	"All uppercase":"[A-Z]*",
	"All lowercase":"[a-z]*",
	"Contains at least 1 special character":'''.*[!@#$%^&*(),.?":{}|<>; ].*''',
	"Only digits":"[0-9]*",
	"4 characters":".{4,4}",
	"5 characters":".{5,5}",
	"6 characters":".{6,6}",
	"7 characters":".{7,7}",
	"8 characters":".{8,8}",
	"9 characters":".{9,9}",
	"10 characters":".{10,10}",
	"11 characters":".{11,11}",
	"12 characters and above":".{12,}",
	"Total":".*",
	}
	found = {x:0 for x in patterns.keys()}
	for pattern, regex in patterns.items():
		for word in creds:
			if re.fullmatch(regex, word):
				found[pattern] += 1
	return found

def format_output(data: dict):
	for key, value in data.items():
		print(f"{key} : {value}")

def parse_args():
    parser = argparse.ArgumentParser(description="Password analyzer")
    parser.add_argument("--passwordfile", help="File containing passwords to be analyzed", required=True, nargs=1)
    parser.add_argument("--mostcommon", help="Find the n most common passwords", required=False, nargs=1, type=int)
    parser.add_argument("--lengths", help="Displays a graph and prints out statistics about password lengths", required=False, action='store_true')
    #parser.add_argument("-a", help="Runs all analysis programs on the password list.", required=False, action='store_true')
    #parser.add_argument("--wordlist", help="Specify a commmon wordlist to be compared to password file to find weak passwords. Rockyou.txt is the default", required=False, type=str, nargs=1)
    parser.add_argument("--showstats", help="Show statistics such as median on the graphs if it applies", required=False, action='store_true')
    parser.add_argument("--pattern", help="Prints out pattern detection from the wordlist", required=False, action="store_true")
    parser.add_argument("--organization", help="Specity an organization name for the title of each graph", required=False, type=str)
    return parser.parse_args()

def main():
	args = parse_args()
	if args.organization == None:
		args.organization = ''
	passwords = load_passwords(args.passwordfile[0], '')
	if args.lengths == True:
		data = get_password_lengths(passwords)
		if args.showstats:
			graph_password_lengths(data, True, args.organization)
		else:
			graph_password_lengths(data, False, args.organization)
	elif args.mostcommon != None:
		print(most_common_passwords(passwords, args.mostcommon[0]))
		most_common_passwords_graph(passwords, args.mostcommon[0], args.organization)
	elif args.pattern != None:
		data = pattern_detection(passwords)
		format_output(data)

if __name__ == "__main__":
	main()
