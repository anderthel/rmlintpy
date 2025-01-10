import logging												# for logging
from tqdm import tqdm										# for tqdm main
from tqdm.contrib.logging import logging_redirect_tqdm		# for tqdm with logging
from pathlib import Path									# for file stuff
import hashlib												# for hashing
from collections import defaultdict							# for quick_pass
from os import removedirs									# for removing empty dirs
from time import time										# for timestamping
import json
from pprint import pprint									# for debugging

# Paths
folder = ""
output = ""
known_hashes = "processed files.json"

# Settings
chunk_size = 1024
testing = False
hide_names = True

# Log stuff
LOG = logging.getLogger("logger5000")
LOG.setLevel(logging.INFO)


def get_hash(file, first_chunk_only=False, hash=hashlib.sha1):
	if LOG.level == logging.DEBUG:
		if hide_names:
			name = f"hashed_name({hashlib.md5(file.name.encode()).hexdigest()})"
		else:
			name = file.name
		LOG.debug(f"Getting hash of: {name}")
	hashobj = hash()
	with open(file, "rb") as f:
		# read first chunk
		hashobj.update(f.read(chunk_size))

		# if not first chunk then read the rest of file
		if not first_chunk_only:
			buf = f.read(chunk_size)
			while len(buf) > 0:
				hashobj.update(buf)
				buf = f.read(chunk_size)

		# convert object to hash
		hashed = hashobj.hexdigest()

	return hashed


def quick_pass(folder):
	# modified from https://stackoverflow.com/questions/748675/finding-duplicate-files-and-removing-them
	files_by_size = defaultdict(list)
	hashes_on_1k = defaultdict(list)
	hashes_on_full = defaultdict(list)
	unique = defaultdict(list)

	# get list of all files and group by same size
	LOG.info("Getting list of files and grouping by size")

	# show tqdm if log level is debug else keep hidden
	for file in (tqdm(list(Path(folder).rglob("*")), leave=False) if LOG.level <= logging.INFO else list(Path(folder).rglob("*"))):
		if file.is_file():
			files_by_size[file.stat().st_size].append(file)

	# remove empty files
	empty = files_by_size.pop(0, "")
	LOG.info(f"Removing {len(empty)} empty file(s)")
	if not testing:
		for file in empty:
			file.unlink()

	LOG.info("Starting first chunk hashes")
	# show tqdm if log level is debug else keep hidden
	for size_bytes, files in (tqdm(files_by_size.items(), leave=False) if LOG.level <= logging.INFO else files_by_size.items()):
		# get all files of the same size
		if len(files) < 2:
			# if file size is unique
			unique[size_bytes].append(files[0])
			continue

		for file in files:
			# if non unique then check 1st chunk_size bytes
			hashes_on_1k[(get_hash(file, first_chunk_only=True), size_bytes)].append(file)

	LOG.info("Starting full hashes")
	for __, files in (tqdm(hashes_on_1k.items(), leave=False) if LOG.level <= logging.INFO else hashes_on_1k.items()):
		# get all files of the same size + small hash
		if len(files) < 2:
			# if size + small hash is unique
			unique[files[0].stat().st_size].append(files[0])
			continue

		# get full hash
		for file in files:
			full_hash = get_hash(file, first_chunk_only=False)
			duplicate = hashes_on_full.get((file.stat().st_size, full_hash))
			if duplicate:
				# if duplicate then delete
				if hide_names:
					name = f"hashed_name({hashlib.md5(file.name.encode()).hexdigest()})"
				else:
					name = file.name
				LOG.warning(f"{name} is duplicate. Removing...")
				if not testing:
					file.unlink(missing_ok=True)
			else:
				hashes_on_full[(file.stat().st_size, full_hash)] = file

	LOG.info("Starting unique full hashes")
	for __, files in (tqdm(unique.items(), leave=False) if LOG.level <= logging.INFO else unique.items()):
		# get full hash
		for file in files:
			full_hash = get_hash(file, first_chunk_only=False)
			duplicate = hashes_on_full.get((file.stat().st_size, full_hash))
			if duplicate:
				# if duplicate then delete
				if hide_names:
					name = f"hashed_name({hashlib.md5(file.name.encode()).hexdigest()})"
				else:
					name = file.name
				LOG.warning(f"{name} is duplicate. Removing...")
				if not testing:
					file.unlink(missing_ok=True)
			else:
				hashes_on_full[(file.stat().st_size, full_hash)] = file

	# return unique + hashes_on_full for more processing
	return hashes_on_full


def main_pass(new):
	unique = []

	# try to load file of known files
	try:
		# raise FileNotFoundError
		with open(known_hashes, "r") as infile:
			hashes = defaultdict(list, json.load(infile))
	except FileNotFoundError:
		hashes = defaultdict(list)

	# for each new file check if exists in hashes file
	for size, hashed in new:
		if (hashed in hashes[str(size)]):
			# if in hashes then delete
			file = new[(size, hashed)]
			if hide_names:
				name = f"hashed_name({hashlib.md5(file.name.encode()).hexdigest()})"
			else:
				name = file.name
			LOG.warning(f"{name} is duplicate. Removing...")
			if not testing:
				file.unlink(missing_ok=True)
		else:
			# if not in hashes then add to unique and store hash
			hashes[str(size)].append(hashed)
			file = new[(size, hashed)]
			if hide_names:
				name = f"hashed_name({hashlib.md5(file.name.encode()).hexdigest()})"
			else:
				name = file.name
			LOG.debug(f"{name} is unique. Keeping...")
			unique.append(file)
	if not testing:
		with open(known_hashes, "w") as outfile:
			json.dump(dict(hashes), outfile)

	LOG.info("Moving processed files")
	if not testing:
		for file in tqdm(unique):
			new = (Path(output) / file.relative_to(Path(folder)))
			# if file exist change name
			if new.exists():
				new = f"{new.parent}/{new.stem} ({time()}){new.suffix}"
			try:
				file.rename(new)
			except FileNotFoundError:
				new.parent.mkdir(parents=True)
				file.rename(new)


def cleanup_empty():
	try:
		for thing in Path(folder).rglob("*"):
			if thing.is_dir() and len(list(thing.iterdir())) == 0:
				removedirs(thing)
	except FileNotFoundError:
		pass


def main():
	# Check paths
	if Path(output).is_relative_to(Path(folder)):
		LOG.critical("Output must not be inside input")
	else:
		LOG.debug("Output and input okay")

	# Run
	start = time()
	LOG.info("Starting quick_pass")
	hashes_on_full = quick_pass(folder)
	main_pass(hashes_on_full)
	LOG.info("Complete. Cleaning up...")
	cleanup_empty()
	LOG.info(f"Runtime: {time() - start}")


if __name__ == '__main__':
	logging.basicConfig(format='[%(asctime)s] - [%(levelname)s]: %(message)s', datefmt="%H:%M:%S")
	with logging_redirect_tqdm():
		main()
