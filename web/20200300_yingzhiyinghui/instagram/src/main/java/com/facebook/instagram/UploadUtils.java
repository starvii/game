package com.facebook.instagram;

import java.util.*;

public class UploadUtils {
    private static final Set<String> AllowedExtName = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList("jpg", "jpeg", "png", "gif")));

    protected static String rename(String path) {
        final String ext = getExtName(path);
        if (ext.length() == 0) {
            return "";
        }
        String suffix = UUID.randomUUID().toString().replaceAll("-", "");
        return System.currentTimeMillis() + "-" + suffix + "." + ext;
    }

    protected static String getExtName(final String filename) {
        final String fn = filename.toLowerCase();
        final int p = fn.lastIndexOf(".");
        if (p < 0) {
            return "";
        }
        final String ext = fn.substring(p + 1);
        if (AllowedExtName.contains(ext)) {
            return ext;
        }
        return "";
    }

//    public static String getDir(String name) {
//        return "";
//    }
}
