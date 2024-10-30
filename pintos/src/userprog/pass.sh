#!/bin/bash

# make check 실행 후 출력 저장
make check | grep 'FAIL' > output.txt

# output.txt에서 "pass"가 있는 줄만 추출
# grep 'pass' output.txt > pass_lines.txt

# cons.txt와 비교하여 "fail"이 있는 줄 삭제
# grep -v 'fail' pass_lines.txt > final_output.txt

# 결과 출력
# cat final_output.txt
# cat pass_lines.txt
