import com.mysql.cj.util.DataTypeUtil;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.sql.Connection;
import java.util.ArrayList;

public class Server {

    //room all clients enter
    //everytime a client enters, broadcast client name
    //client send name first (verify unused name)
    //each client has his name and it is added during broadcasting
    //creating client commands
    //creating server commands
    PublicKey publicKey;
    PrivateKey privateKey;
    SecretKey sessionKeyServer;
    ArrayList<String> clientNames = new ArrayList<>();
    ArrayList<String> clientNumbers = new ArrayList<>();
    final ArrayList<ClientHandler> clientHandlerArrayList = new ArrayList<>();
    boolean serverIsOn;

    Server() {
        serverIsOn = true;
        try {
           KeyPair kp = Crypto.generateKeyPair();
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
           } catch (Exception e) {
            e.printStackTrace();
        }
        // Connection connection = javaDB.getConnection();

        //  if (connection!=null)
        clientNumbers = javaDB.getClientNumber() ;

        try {
            //Data type تقوم بعمل Socket من نوع استماع
            //حيث تستسمع للاتصالات وتجهز بيانات المتصل وتعيد socket فيهاالبيانات

            ServerSocket serverSocket = new ServerSocket(22000);

            /*
            كود سحب الأرقام من قاعدة البيانات
            وتخزينها في clientNumber
             */

            //for accepting the connection
            //اي اتصالات قادمة يتم قبولها هنا
            Thread handlingIncomingConnections = new Thread() {
                @Override
                public void run() {
                    try {
                        while (serverIsOn) {
                            System.out.println("server is on");
                            Socket clientSocket = serverSocket.accept();
                            System.out.println("Client Accepted");
                            ClientHandler clientHandler0 = new ClientHandler(clientSocket);
                            //The code for check the information in the database
                            if(javaDB.checkInformationInDataBase( clientHandler0.getClientNumber() , clientHandler0.getClientPassword()))
                            {
                                System.out.println("Login is done");
                                //إضافة رقم العميل لمصفوفة العملاء المرتبطين بالسيرفر
                                // فك التعليق سيكون بعد الإضافة من الداتا بيز
                                //  clientNumbers.add(clientHandler0.getClientNumber()) ;

                                clientHandler0.sendOtherClientsNumbers(clientNumbers) ;

                                //إدخال العميل
                                synchronized (clientHandlerArrayList) {
                                    clientHandlerArrayList.add(clientHandler0) ;
                                }
                                clientHandler0.sendPublicKey(publicKey);

                                sessionKeyServer =  clientHandler0.getSessionKey(privateKey);

                                System.out.println("SESSION KEY SERVER : " + DatatypeConverter.printHexBinary(sessionKeyServer.getEncoded()));

                                //هنا يتم التأكد هل الكلاينت الذي أريد التواصل معه في حالة اتصال مع السيرفر
                                //إذا كان موجود يتم التواصل معه و إلا انتظار دخول هذا العميل لإرسال الرسائل له

                                String connectionNumber = clientHandler0.receiveConnectionNumber() ;
                                for (int i = 0 ; i < clientHandlerArrayList.size() ; i++)
                                {
                                    if (clientHandler0.getConnectionNumber().equals(clientHandlerArrayList.get(i).getClientNumber()))
                                    {
                                        System.out.println("hhhhhhhhhhhhhhhhhhaaaaaaaaaaaaaaaaaa");
                                        clientHandler0.start();
                                        clientHandlerArrayList.get(i).start();
                                        clientHandler0.makeConnectionWithAnotherClient(clientHandlerArrayList.get(i) ) ;
                                    }
                                }
        }
                            /*else{
                                Person person = new Person();
                                person.setNumber(Integer.parseInt(clientHandler0.clientNumber));
                                person.setPassword(clientHandler0.getClientPassword());
                                person.setClient_key(generateKey());
                                javaDB.insert(person);//End of if statement
                            }*/
                        }//End of while statement
                    } catch (Exception ex) {
                        ex.printStackTrace() ;
                    }
                }//End of run method
            }; //End of handlingIncomingConnections
            handlingIncomingConnections.start() ;



        }catch(IOException e){
            e.printStackTrace();

        }
    }


    public void printAllUserNames()
    {
        System.out.println(clientNames);
    }

    public void printUserCount()
    {
        System.out.println(clientNames.size());
    }

}

