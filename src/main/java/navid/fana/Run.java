package navid.fana;

import navid.fana.agent.SimpleAgent;

import java.io.File;
import java.io.IOException;

public class Run {
    public static void main(String[] args){
        SimpleAgent agent = null;
        try {
            agent = new SimpleAgent("127.0.0.1/2001");
            agent.start();
            while(true) {
                System.out.println("Agent running...");
                Thread.sleep(5000);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}

