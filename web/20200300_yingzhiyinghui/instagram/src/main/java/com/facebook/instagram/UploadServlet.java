package com.facebook.instagram;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

@WebServlet("/upload.action")
@MultipartConfig
public class UploadServlet extends HttpServlet {
    private static final long serialVersionUID = -1;
    private static final String UPLOAD = "upload/";

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=utf-8");
        response.getWriter().print("Not Allowed Method");
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // 获取文件上传组件
        final Part part = request.getPart("file");

        // 获取文件的路径
        final String header = part.getHeader("content-disposition");
        final String originalFilename = header.substring(header.indexOf("filename=") + 10, header.length() - 1);

        // 获取文件名
        final String newName = UploadUtils.rename(originalFilename);

        if (newName.length() == 0) {
            response.setContentType("text/html;charset=utf-8");
            response.getWriter().print("非法文件类型！<br/>只允许jpg/png/gif文件哦~");
            return;
        }
//        // 获取文件的存放目录
//        String dir = UploadUtils.getDir(name);
//
        final String path = this.getServletContext().getRealPath("/") + UPLOAD;

//        String realPath = this.getServletContext().getRealPath("/upload/" + name);
        File file = new File(path);
        if (!file.exists()) {
            if (!file.mkdirs()) {
                response.setContentType("text/html;charset=utf-8");
                response.getWriter().print("上传目录创建失败。请联系管理员。");
                return;
            }
        }

        // 对拷流
        InputStream inputStream = part.getInputStream();
        FileOutputStream outputStream = new FileOutputStream(new File(file, newName));
        int len = -1;
        byte[] bytes = new byte[1024];
        while ((len = inputStream.read(bytes)) != -1) {
            outputStream.write(bytes, 0, len);
        }

        // 关闭资源
        outputStream.close();
        inputStream.close();

        // 删除临时文件
        part.delete();

        response.setContentType("text/html;charset=utf-8");
        response.getWriter().print("文件 " + originalFilename + " 上传成功！");
        response.getWriter().print("<br/>文件路径：" + request.getContextPath() + "/" + UPLOAD + newName);

    }
}
