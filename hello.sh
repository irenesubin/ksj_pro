#!/bin/bash

# 출력 디렉토리 설정
output_dir="/home/rocky1"
output_file="$output_dir/경고!보시오.txt"

# 디렉토리가 존재하지 않으면 생성
mkdir -p "$output_dir"

# 메시지와 날짜를 파일에 출력
echo "안녕하세요! 이 스크립트가 실행되었어요!" > "$output_file"
date >> "$output_file"

# 파일이 성공적으로 생성되었는지 확인
if [ -f "$output_file" ]; then
    echo "파일이 성공적으로 생성되었습니다: $output_file"
else
    echo "파일 생성에 실패했습니다."
fi
