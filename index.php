<?php 
    include_once("config.php");

    $result = mysqli_query($mysqli, "SELECT * FROM student ORDER BY id DESC");
?>

<html>
    <head>
        <title>Student management</title>
    </head>
    <body>
        <a href="create.php">Add new student</a>

        <table width='90%' border=1>
            <tr>
                <th>Name</th> <th>Mobile</th> <th>Email</th> <th>Update</th>
            </tr>
            <?php 
                while($student_data = mysqli_fetch_array($result)) {
                    echo "<tr>";
                    echo "<td>".$student_data['name']."</td>";
                    echo "<td>".$student_data['mobile']."</td>";
                    echo "<td>".$student_data['email']."</td>";
                    echo "<td><a href='edit.php?id=$student_data[id]'>Edit</a> | 
                    <a href='delete.php?id=$student_data[id]'>Delete</a></td></tr>";    
                }
            ?>
        </table>
    </body>
</html>