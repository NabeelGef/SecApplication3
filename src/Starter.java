import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Starter {

    public static void main(String[] args) throws Exception {
        Scanner myInput = new Scanner(System.in) ;

        Thread firstThread = new Thread()
        {
            @Override
            public void run() {

                while (true)
                {
                    System.out.println("Thread is active1");

                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        // firstThread.start();

        String m = myInput.next();
        if (m.equals("Server"))
        {
            //Server code
            Server server = new Server();

            while (true)
            {
                String str = myInput.next();
                if (str.equals("all"))
                {
                    server.printAllUserNames();

                }else if (str.equals("count"))
                    server.printUserCount();
            }
        }

        else if (m.equals("Client"))
        {
            /*
            //Client code
                    //التواصل مع قاعدة البيانات

                    /*if (check with the data base)
                       {

                       Client client = new Client(person);
                       }


                    //إذا كان موجود قم بعرض خياراته(أرقامه مع أرقام باقي العملاء في السيرفر)

                    break;


                case 2:
                    break;
            }
        */

            System.out.println("Enter your number :");
            String clientNumber = myInput.next();

            System.out.println("Enter your password :");
            String clientPassword = myInput.next();


            Client client = new Client(clientNumber , clientPassword);


            System.out.println("Choose the number to connect");
            int connectNumber = myInput.nextInt() ;
        }

    }
}
