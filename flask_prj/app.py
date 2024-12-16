from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import json
import glob
import os
import matplotlib.pyplot as plt
import numpy as np
import io
import base64
from collections import defaultdict
import matplotlib.font_manager as fm
import ssl
import uuid
import pdfkit
from datetime import datetime
from urllib.parse import unquote

# 환경 변수 설정
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# 한글 폰트 설정
font_path = '/usr/share/fonts/truetype/nanum/NanumGothic.ttf'
font_prop = fm.FontProperties(fname=font_path)
plt.rcParams['font.family'] = 'NanumGothic'
plt.rcParams['axes.unicode_minus'] = False

app = Flask(__name__,
    static_folder='static',
    template_folder='templates')

# 시크릿 키 설정
app.secret_key = 'c09c554591464907941a2a5f36e03b14'

def create_category_chart(data):
    # 카테고리별 결과 집계
    results_by_category = defaultdict(lambda: {'vulnerable': 0, 'good': 0, 'na': 0})

    for detail in data['details']:
        category = detail['category']
        if '취약' in detail['result']:
            results_by_category[category]['vulnerable'] += 1
        elif '양호' in detail['result']:
            results_by_category[category]['good'] += 1
        else:
            results_by_category[category]['na'] += 1

    # 그래프 생성
    plt.figure(figsize=(15, 6))

    categories = list(results_by_category.keys())
    x = np.arange(len(categories))
    width = 0.25

    plt.bar(x - width, [results_by_category[cat]['vulnerable'] for cat in categories],
            width, label='취약', color='#dc3545', alpha=0.8)
    plt.bar(x, [results_by_category[cat]['good'] for cat in categories],
            width, label='양호', color='#28a745', alpha=0.8)
    plt.bar(x + width, [results_by_category[cat]['na'] for cat in categories],
            width, label='N/A', color='#6c757d', alpha=0.8)

    plt.xlabel('카테고리',fontsize=17, labelpad=15)
    plt.ylabel('항목 수',fontsize=17, labelpad=15)
    plt.title('카테고리별 점검 결과',fontsize=17, pad=30)
    plt.xticks(x, categories, rotation=0, ha='center', fontsize=17, y=-0.02 )
    plt.legend(fontsize=16)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    # 이미지를 base64로 인코딩
    img = io.BytesIO()
    plt.savefig(img, format='png', dpi=300, bbox_inches='tight')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    plt.close()

    return plot_url


@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/account', methods=['GET'])
def server_account():
    return render_template('server_account.html')

@app.route('/script', methods=['GET', 'POST'])
def script():
    if request.method == 'POST':
        server_data = request.form.getlist('server_data')
        servers = []
        for data in server_data:
            server_info = json.loads(data)
            servers.append(server_info)
        return render_template('script.html', servers=servers)
    return render_template('script.html')

@app.route('/result', methods=['GET', 'POST'])
def result():
    if request.method == 'POST':
        server_os = request.form.get('server_os')
        ip_address = request.form.get('ip_address')
    else:
        server_os = request.args.get('os')
        ip_address = request.args.get('ip')
    
    json_file_pattern = '/tmp/results/results*.json'
    json_files = glob.glob(json_file_pattern)
    
    if json_files:
        latest_file = max(json_files, key=os.path.getctime)
        with open(latest_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
            
        plot_url = create_category_chart(data)
        
        filter_type = request.args.get('filter', 'all')
        filtered_data = data['details']
        
        if filter_type == 'vulnerable':
            filtered_data = [item for item in data['details'] if '취약' in item['result']]
        elif filter_type == 'good':
            filtered_data = [item for item in data['details'] if '양호' in item['result']]
        elif filter_type == 'na':
            filtered_data = [item for item in data['details'] if not ('취약' in item['result'] or '양호' in item['result'])]
            
        return render_template('result.html', 
                             data=data, 
                             filtered_data=filtered_data,
                             current_filter=filter_type,
                             plot_url=plot_url,
                             server_os=server_os,
                             ip_address=ip_address)


@app.route('/download-pdf')
def download_pdf():
    try:
        # JSON 파일에서 데이터를 다시 로드
        json_file_pattern = '/tmp/results/results*.json'
        json_files = glob.glob(json_file_pattern)
        
        if not json_files:
            return "결과 파일을 찾을 수 없습니다.", 404
        
        latest_file = max(json_files, key=os.path.getctime)
        with open(latest_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # 그래프 URL 생성
        plot_url = create_category_chart(data)
        
        # 필터링 데이터 처리 (기본값: all)
        filter_type = request.args.get('filter', 'all')
        filtered_data = data['details']
        
        if filter_type == 'vulnerable':
            filtered_data = [item for item in data['details'] if '취약' in item['result']]
        elif filter_type == 'good':
            filtered_data = [item for item in data['details'] if '양호' in item['result']]
        elif filter_type == 'na':
            filtered_data = [item for item in data['details'] if not ('취약' in item['result'] or '양호' in item['result'])]

        # URL에서 os와 ip 파라미터를 정확히 가져오기
        ip_address = request.args.get('ip', '').strip()
        
        # os나 ip 값이 없을 경우 기본값을 설정
        ip_address = ip_address.strip() if ip_address else 'unknown'
    
        current_time = datetime.now().strftime('%Y%m%d_%H%M')
        print(f"IP Address: {ip_address}")

        # PDF 파일 이름 생성
        pdf_filename = f"result_{ip_address}_{current_time}.pdf"

        # HTML 렌더링
        html = render_template('result.html', 
                               data=data,
                               filtered_data=filtered_data,
                               current_filter=filter_type,
                               plot_url=plot_url,
                               ip_address=ip_address)
        
        # PDF 생성
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'enable-local-file-access': None
        }
        
        pdf = pdfkit.from_string(html, False, options=options)
        
        # PDF 응답 반환
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={pdf_filename}'
        
        return response
        
    except Exception as e:
        return f"PDF 생성 중 오류가 발생했습니다: {str(e)}", 500


if __name__ == '__main__':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile='/home/flask_prj/cert.pem', 
        keyfile='/home/flask_prj/key.pem'
    )
    app.run(host='0.0.0.0', port=443, ssl_context=ssl_context,debug=True)