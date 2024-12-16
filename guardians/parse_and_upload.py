import json
import requests
import sys
import os

def parse_txt_to_json(txt_file):
    data = []
    summary = {}
    current_item = {}

    with open(txt_file, "r", encoding="utf-8") as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()

        # 빈 줄이나 불필요한 헤더/푸터 무시
        if not line or line.startswith("#") or line.startswith("점검일") or line.startswith("="):
            continue

        # 진단 결과 요약 분리
        if line.startswith("★ 항목 개수"):
            summary["total_items"] = int(line.split("=")[-1].strip())
            continue
        elif line.startswith("☆ 취약 개수"):
            summary["vulnerable_items"] = int(line.split("=")[-1].strip())
            continue
        elif line.startswith("★ 양호 개수"):
            summary["good_items"] = int(line.split("=")[-1].strip())
            continue
        elif line.startswith("☆ N/A 개수"):
            summary["na_items"] = int(line.split("=")[-1].strip())
            continue

        # ID 및 카테고리 정보 파싱
        if line.startswith("▶ U-"):
            if current_item:  # 이전 항목 저장
                # 현재 상태와 양호 판단 기준 기본값 처리
                current_item.setdefault("current_status", "N/A")
                current_item.setdefault("criteria", "N/A")
                data.append(current_item)
            current_item = {}

            # ID 및 중요도 추출
            id_and_category = line.split("|")
            current_item["id"] = id_and_category[0].split("▶")[-1].strip()
            current_item["importance"] = id_and_category[0].split("(")[-1].split(")")[0].strip()

            # 카테고리 및 점검 항목 처리
            category_info = id_and_category[1].strip()
            category_split = category_info.split(">")
            current_item["category"] = category_split[0].strip() if len(category_split) > 0 else "N/A"
            current_item["check_item"] = category_split[1].strip() if len(category_split) > 1 else "N/A"

        # 양호 판단 기준
        elif line.startswith("양호 판단 기준"):
            current_item["criteria"] = line.split("양호 판단 기준 :")[-1].strip()

        # 결과 파싱
        elif line.startswith("※"):
            current_item["result"] = line.split("결과 :")[-1].strip()

        # 상태 설명 추가
        elif current_item and "result" in current_item:
            # 진단 결과 요약이 아닌 경우에만 추가
            if not line.startswith("★") and not line.startswith("☆"):
                if "current_status" not in current_item:
                    current_item["current_status"] = line
                else:
                    current_item["current_status"] += f" {line}"

    # 마지막 항목 저장
    if current_item:
        current_item.setdefault("current_status", "N/A")
        current_item.setdefault("criteria", "N/A")
        data.append(current_item)

    return data, summary

def save_json_to_file(json_data, summary, txt_file):
    # JSON 파일 이름 생성
    base_name = os.path.basename(txt_file)
    json_file = os.path.join("/tmp/results", f"{os.path.splitext(base_name)[0]}.json")
    
    # JSON 데이터 생성
    output = {
        "summary": summary,
        "details": json_data
    }

    # JSON 데이터 저장
    print(f"Saving JSON data to: {json_file}")  # 디버깅용 출력
    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(output, file, ensure_ascii=False, indent=4)
    
    print(f"JSON 파일 저장 완료: {json_file}")
    return json_file

def upload_json(json_file, server_url):
    # JSON 파일 로드 후 업로드
    try:
        with open(json_file, "r", encoding="utf-8") as file:
            json_data = json.load(file)

        print("Uploading JSON data:", json.dumps(json_data, ensure_ascii=False, indent=4))  # 디버깅용 출력
        response = requests.post(server_url, json=json_data, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            print("JSON 데이터 업로드 성공!")
        else:
            print(f"업로드 실패: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error during upload: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("사용법: python3 parse_and_upload.py <txt_file> <server_url>")
        sys.exit(1)

    txt_file = sys.argv[1]
    server_url = sys.argv[2]

    print(f"Parsing TXT file: {txt_file}")  # 디버깅용 출력
    json_data, summary = parse_txt_to_json(txt_file)
    json_file = save_json_to_file(json_data, summary, txt_file)
    upload_json(json_file, server_url)
