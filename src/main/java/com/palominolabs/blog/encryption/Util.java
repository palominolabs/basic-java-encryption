package com.palominolabs.blog.encryption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

final class Util {

    /**
     * Read a line of input
     *
     * @return The bytes of input read
     */
    static String readInput(String prompt) {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        String result;
        while (true) {
            System.out.println(prompt);

            try {
                result = br.readLine();
            } catch (IOException e) {
                System.err.println("Error reading input");
                e.printStackTrace();
                continue;
            }

            if (result.isEmpty()) {
                System.err.println("Please provide some input!");
                System.err.flush();
            } else {
                break;
            }
        }
        return result;
    }
}
