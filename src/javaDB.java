import java.sql.*;
import java.util.ArrayList;

public class javaDB {



    public static void main(String[] args)
    {
        // getConnection() ;

        //inserting for the database
        Person person = new Person();
        person.setClient_key("i am the first client");
        person.setNumber(6789);
        person.setPassword("123");
        insert(person);
       /* ArrayList<Person> personArrayList = getPersons();
        for (int i = 0 ; i < personArrayList.size() ; i++)
        {
            System.out.print(personArrayList.get(i).getNumber());
            System.out.print(personArrayList.get(i).getPassword());
            System.out.println();
        }*/



    }

    //Make a connection with database
    public static Connection getConnection()
    {
        try {
            Class .forName("com.mysql.cj.jdbc.Driver"); //The new connector with database
            // Class.forName("com.mysql.jdbc.Driver"); //Connector with database
            String url = "jdbc:mysql://localhost:3306/" ; //java data base connectivity
            String  dataBaseName = "testproject" ;
            String  userName = "root" ;
            String  password = "" ;
            Connection connection = DriverManager.getConnection(url+dataBaseName , userName ,password );
            System.out.println("Connected successfully");
            return connection ;
        }
        catch (Exception ex)
        {
            System.out.println("Could not connect with data base");
            ex.printStackTrace();
        }

        return null;
    }

    //Insert new client
    public static void insert(Person person) //put the parameter of the function
    {
        Connection connection = getConnection();
        PreparedStatement statement ;
        try {
            // String sqlInsertStatement = "INSERT INTO 'column name'('id' , 'name' , 'age') Values( , , )" ; //the statement for inserting the data on the DB
            String sqlInsertStatement = "INSERT INTO `person` (`id`, `number`, `client_key`, `password`) VALUES (NULL, ? , ? , ? )" ;
            //assert connection != null;
            statement = connection.prepareStatement(sqlInsertStatement); //لتحضير قاعدة البيانات للاستقبال
            statement.setInt(1 , person.getNumber()); //1 تعني مكان أول إشارة استفهام
            statement.setString(2 , person.getClient_key());
            statement.setString(3 , person.getPassword());
            statement.execute();
            connection.close();
        }catch(SQLException ex)
        {
            System.out.println("Could not insert data");
            ex.printStackTrace();
        }
    }

    //Get all clients from the database
    public static ArrayList<Person> getClientInformation()
    {
        Connection connection = getConnection();
        Statement statement ;
        ArrayList<Person>  personArrayList = new ArrayList<>() ;

        try {
            statement = connection.createStatement() ;
            ResultSet resultSet = statement.executeQuery("select number , password from person") ;//for saving the result of the query

            while (resultSet.next())
            {
                Person person = new Person();
                person.setNumber(resultSet.getInt("number"));
                person.setPassword(resultSet.getString("password"));
                personArrayList.add(person) ;

            }
            connection.close();
            return personArrayList ;
        } catch (SQLException sqlException) {
            sqlException.printStackTrace();
        }
        return null ;
    }


    //Check the information of login
    public static boolean checkInformationInDataBase(String number , String password)
    {
        ArrayList<Person> allClients = getClientInformation() ;
        System.out.println("IN DB!!!!");
        if (allClients!=null)
            for (int i = 0 ; i < allClients.size() ; i++)
            {
                if (allClients.get(i).getNumber() == Integer.parseInt(number))
                {
                    if (allClients.get(i).getPassword().equals(password)) {
                        return true;
                    }

                    else
                    {

                        return false ;
                    }
                }
            }
        return false ;
    }

    //For deleting a client
    public static int deleteClient( int id )
    {
        Connection connection = getConnection() ;
        PreparedStatement preparedStatement ;


        try {
            preparedStatement = connection.prepareStatement("delete from person where id=?") ;
            preparedStatement.setInt( 1 , id );

            int i =preparedStatement.executeUpdate() ; //تعيد قيمة ولا تكون -1 بل عدد العمليات التي تمت بشكل صحيح أو بشكل خاطئ
            connection.close() ;
            return i ;

        } catch (SQLException sqlException) {
            sqlException.printStackTrace();
        }

        return -1 ; //there is a problem
    }

    //For getting a key for specific client by number
    public static String getClientKey(String number)
    {
        Connection connection = getConnection();
        Statement statement ;
        Person  person = new Person() ;

        try {
            statement = connection.createStatement() ;
            ResultSet resultSet = statement.executeQuery("select client_key from person where number = "+number) ;//for saving the result of the query

            while (resultSet.next())
            {
                person.setClient_key(resultSet.getString("client_key"));
            }
            connection.close();
            return person.getClient_key() ;
        } catch (SQLException sqlException) {
            sqlException.printStackTrace();
        }
        return null ;
    }


    public static ArrayList<String> getClientNumber()
    {
        Connection connection = getConnection();
        Statement statement ;
        ArrayList<String>  clientNumbers = new ArrayList<>() ;

        try {
            statement = connection.createStatement() ;
            ResultSet resultSet = statement.executeQuery("select number from person") ;//for saving the result of the query

            while (resultSet.next())
            {
                clientNumbers.add(resultSet.getInt("number")+"") ;

            }
            connection.close();
            return clientNumbers ;
        } catch (SQLException sqlException) {
            sqlException.printStackTrace();
        }
        return null ;
    }
}
