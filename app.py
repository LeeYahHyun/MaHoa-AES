
from flask import Flask, render_template, request, jsonify, send_from_directory

# Import thuật toán AES từ index.py
from index import make_key, convert

# Cho Flask tìm HTML ngay tại thư mục hiện tại
app = Flask(__name__, template_folder=".")


# Hiển thị giao diện HTML
@app.route("/")
def home():
    return render_template("index.html")


# Cung cấp file JavaScript ở thư mục gốc
@app.route("/index.js")
def javascript():
    return send_from_directory(app.root_path, "index.js")


# Xử lý mã hóa và giải mã
@app.route("/convert", methods=["POST"])
def process_aes():
    try:
        data = request.get_json()

        input_text = data.get("input", "")
        password = data.get("key", "")
        mode = data.get("mode", "")

        if not input_text:
            raise ValueError("Vui lòng nhập dữ liệu!")

        if not password:
            raise ValueError("Vui lòng nhập khóa!")

        if mode not in ("enc", "dec"):
            raise ValueError("Chế độ không hợp lệ!")

        # Tạo khóa AES-128
        key = make_key(password)

        # Gọi thuật toán AES code tay
        kind, result = convert(input_text, key, mode)

        return jsonify({
            "success": True,
            "kind": kind,
            "result": result
        })

    except (ValueError, UnicodeDecodeError) as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
