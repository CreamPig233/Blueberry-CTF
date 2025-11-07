# web/blueprints/cas.py
import requests
from flask import Blueprint, request, flash, redirect, url_for, session, current_app, abort, render_template
from util.db import db_pool
from passlib.hash import bcrypt_sha256
import json
import secrets

bp = Blueprint('cas', __name__, url_prefix='/cas')

def login_from_neucas(username: str, password: str):
    from bs4 import BeautifulSoup, Tag
    from requests import Session
    
    headers = {
    'User-Agent':"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    }
    
    target = '''https://pass.neu.edu.cn/tpass/login?service=https%3A%2F%2Fpersonal.neu.edu.cn%2Fportal%2Fmanage%2Fcommon%2Fcas_login%2F1%3Fredirect%3Dhttps%253A%252F%252Fpersonal.neu.edu.cn%252Fportal%252Fpersonal%252Ffrontend%252Fdata%252Finfo'''

    session = Session()
    
    page_soup = BeautifulSoup(session.get(target).text, "html.parser")
    form: Tag = page_soup.find("form", {'id': 'loginForm'})
    page = {
        "form_lt_string": form.find("input", {'id': 'lt'}).attrs["value"],
        "form_destination": form.attrs['action'],
        "form_execution": form.find("input", {'name': 'execution'}).attrs["value"]
    }
    
    form_data = {
        'rsa': username + password + page['form_lt_string'],
        'ul': len(username),
        'pl': len(password),
        'lt': page['form_lt_string'],
        'execution': page['form_execution'],
        '_eventId': 'submit'
    }
    login_result = session.post("https://pass.neu.edu.cn" + page['form_destination'], data=form_data, allow_redirects=True)  # 允许跳转
    login_result_soup = BeautifulSoup(login_result.text, "html.parser")
    title_soup = login_result_soup.find("title")

    if title_soup is None:
        login_result = login_result_soup
        return login_result

    if title_soup.text == "智慧东大--统一身份认证":
        raise Exception("登录用户名或密码错误")
    elif title_soup.text == "系统提示":
        raise Exception("预期外异常")
    elif title_soup.text == "智慧东大":
        # 提示未绑定邮箱
        login_result = session.get(target, allow_redirects=True)
        login_result_soup = BeautifulSoup(login_result.text, "html.parser")
        login_result = login_result_soup
        return login_result


@bp.route('/login', methods=['GET', 'POST'])
def cas_login():
    if request.method == 'GET':
        return render_template('user/logincas.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        flash('请输入用户名和密码', 'error')
        return redirect(url_for('cas.cas_login'))

    try:
        # 调用 CAS 认证接口（模拟或真实）
        data = json.loads(str(login_from_neucas(username, password)))

        
        # 预期格式: {"e":0,"m":"操作成功","d":{"info":{"name":"张三","xgh":"20230001","depart":"计算机学院"}}}
        if data.get('e') != 0:
            flash(f"CAS 认证失败: {data.get('m', '未知错误')}", 'error')
            #return redirect(url_for('cas.cas_login'))

        info = data.get('d', {}).get('info', {})
        real_name = info.get('name')
        xgh = info.get('xgh')  # 唯一学工号
        depart = info.get('depart', '')

        # 使用 xgh 作为唯一标识（存入 email 字段，避免与本地用户冲突）
        cas_email = f"{xgh}@cas.local"


        with db_pool.connection() as conn:
            # 查找是否已有该用户（通过 email = xgh@cas.local）
            user = conn.execute(
                'SELECT * FROM user_info WHERE email = %s',
                [cas_email]
            ).fetchone()

            if not user:
                # 自动注册新用户
                # 用户名使用 real_name（注意：可能重复，但系统允许？若不允许可拼接 xgh）
                display_username = real_name
                # 为避免用户名重复，可改用：display_username = f"{real_name}_{xgh}"
                pwd_hash = bcrypt_sha256.hash(secrets.token_urlsafe(32))  # 随机密码，禁止本地登录

                conn.execute(
                    '''INSERT INTO user_info (username, email, password, is_visible, extra_info)
                       VALUES (%s, %s, %s, true, %s)''',
                    [display_username, cas_email, pwd_hash, str(info)]
                )
                user = conn.execute(
                    'SELECT * FROM user_info WHERE email = %s',
                    [cas_email]
                ).fetchone()


            # 登录成功，设置 session
            session['user_id'] = user['id']
            flash(f'欢迎，{real_name}！', 'success')
            return redirect(url_for('show_index'))

    except requests.RequestException as e:
        current_app.logger.error(f"CAS 请求失败: {e}")
        flash('认证服务暂时不可用，请稍后再试', 'error')
        print('认证服务暂时不可用，请稍后再试')
        return redirect(url_for('cas.cas_login'))
    except Exception as e:
        current_app.logger.exception("CAS 登录异常")
        flash(f'登录失败: {str(e)}', 'error')
        print(f'登录失败: {str(e)}')
        return redirect(url_for('cas.cas_login'))