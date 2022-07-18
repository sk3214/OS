import sys
import subprocess


def score_arg_passing(echo_call, test_num):

    ### Run test_arg_passing.sh script
    result = subprocess.Popen(['pa2_student_test/test_arg_passing.sh', echo_call],
             stdout=subprocess.PIPE,
             stderr=subprocess.STDOUT)

    stdout, stderr = result.communicate()

    print(stdout)
    print('-----')
    
    with open('pa2_student_test/gold_' + str(test_num) +  '.txt', 'r') as f:
        gold = f.read()

    gold = ''.join(gold)

    out_dump = []
    for line in stdout.splitlines():
        if 'bfff' in line:
            out_dump.append(line+'\n')

    out_dump = ''.join(out_dump)

    return 100 if (gold.splitlines() == out_dump.splitlines()) else 0


if __name__ == '__main__':
    score1 = score_arg_passing("echo 1", 1) / 5
    score2 = score_arg_passing("echo no padding!", 2) / 5
    score3 = score_arg_passing("echo 3 bytes please!", 3) / 5
    score4 = score_arg_passing("echo this needs 2 bytes of padding", 4) / 5
    score5 = score_arg_passing("cat", 5) / 5
    score = score1 + score2 + score3 + score4 + score5
    print("Score for pa2_phase_1: " + str(score))
