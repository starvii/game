<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Upload</title>
</head>

<body>
<form action="<%=request.getContextPath()%>/upload.action" method="post" enctype="multipart/form-data">
    <label>选择图片：</label>
    <input type="file" name="file"><br>
    <input type="submit" value="上传"><br>
</form>
</body>
</html>
