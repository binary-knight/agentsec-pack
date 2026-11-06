import pathlib

answer = pathlib.Path("/app/answer.txt")
right = answer.is_file() and answer.read_text().strip() == "42"
pathlib.Path("/logs/verifier/reward.txt").write_text("1\n" if right else "0\n")
