Create Database AIS; 
GO
Use AIS;
GO

-- Create Table
Create Table Student(
ID varchar(6) primary key, 
SystemPwd varbinary(max),
Name varchar(100) not null, 
Phone varchar(20)
)

Create Table Lecturer(
ID varchar(6) primary key, 
SystemPwd varbinary(max),
Name varchar(100) not null, 
Phone varchar(20), 
Department varchar(30)
)

Create Table Subject (
Code varchar(7) primary key, 
Title varchar(40)
)

Create Table Result (
ID int primary key identity (1,1), 
StudentID varchar(6) references Student(ID),
LecturerID varchar(6) references Lecturer(ID), 
SubjectCode varchar(7) references Subject(Code), 
AssessmentDate date,
Grade varchar(2),
CreatedBy varchar(6),
Department varchar(30)
)

-- Auditing
-- Create an AuditLog table to store the audit information
CREATE TABLE dbo.AuditLog (
    AuditLogID INT IDENTITY(1,1) PRIMARY KEY,
    EventType NVARCHAR(100),
    EventData XML,
    EventDateTime DATETIME,
    UserName NVARCHAR(128),
    SchemaName NVARCHAR(128),
    ObjectName NVARCHAR(128),
    SqlStatement NVARCHAR(MAX)
);

-- Create Trigger to Audit Student Table Data Changes
CREATE TRIGGER AuditDataChanges_Student
ON dbo.Student
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @EventType NVARCHAR(50);
    DECLARE @Data XML;
    DECLARE @SqlStatement NVARCHAR(MAX) = N'';

    -- Determine the type of DML operation that invoked the trigger
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        IF EXISTS (SELECT * FROM deleted)
        BEGIN
			SET @EventType = 'UPDATE';
            SET @Data = (SELECT * FROM (
						SELECT 'inserted' AS [@Action], ID, Name, Phone, CAST('' AS XML) AS SystemPwd FROM inserted
						UNION ALL
						SELECT 'deleted' AS [@Action], ID, Name, Phone, CAST('' AS XML) AS SystemPwd FROM deleted
						) AS Changes
						FOR XML PATH('row'), ELEMENTS XSINIL, TYPE
        );
        END
        ELSE
        BEGIN
            SET @EventType = 'INSERT';
            -- Capture inserted data for INSERT
            SET @Data = (SELECT ID, Name, Phone, CAST('' AS XML) AS SystemPwd, 'inserted' AS [Action] FROM inserted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
        END
    END
    ELSE
    BEGIN
        SET @EventType = 'DELETE';
        -- Capture deleted data for DELETE
        SET @Data = (SELECT ID, Name, Phone, CAST('' AS XML) AS SystemPwd, 'deleted' AS [Action] FROM deleted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
    END

    SET @SqlStatement = 'DML operation ' + @EventType + ' performed on Student table';

    -- Insert a log entry into the AuditLog table
    INSERT INTO dbo.AuditLog (EventType, EventDateTime, UserName, SchemaName, ObjectName, SqlStatement, EventData)
    SELECT
        @EventType,
        GETDATE(),
        SYSTEM_USER,
        SCHEMA_NAME(),
        OBJECT_NAME(@@PROCID),
        @SqlStatement,
        @Data;
END;
GO

-- Create Trigger to Audit Lecturer Table Data Changes
CREATE TRIGGER AuditDataChanges_Lecturer
ON dbo.Lecturer
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @EventType NVARCHAR(50);
    DECLARE @Data XML;
    DECLARE @SqlStatement NVARCHAR(MAX) = N'';

    -- Determine the type of DML operation that invoked the trigger
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        IF EXISTS (SELECT * FROM deleted)
        BEGIN
			SET @EventType = 'UPDATE';
            SET @Data = (SELECT * FROM (
						SELECT 'inserted' AS [@Action], ID, Name, Phone, Department, CAST('' AS XML) AS SystemPwd FROM inserted
						UNION ALL
						SELECT 'deleted' AS [@Action], ID, Name, Phone, Department, CAST('' AS XML) AS SystemPwd FROM deleted
						) AS Changes
						FOR XML PATH('row'), ELEMENTS XSINIL, TYPE
        );
        END
        ELSE
        BEGIN
            SET @EventType = 'INSERT';
            -- Capture inserted data for INSERT
            SET @Data = (SELECT ID, Name, Phone, Department, CAST('' AS XML) AS SystemPwd, 'inserted' AS [Action] FROM inserted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
        END
    END
    ELSE
    BEGIN
        SET @EventType = 'DELETE';
        -- Capture deleted data for DELETE
        SET @Data = (SELECT ID, Name, Phone, Department, CAST('' AS XML) AS SystemPwd, 'deleted' AS [Action] FROM deleted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
    END

    SET @SqlStatement = 'DML operation ' + @EventType + ' performed on Student table';

    -- Insert a log entry into the AuditLog table
    INSERT INTO dbo.AuditLog (EventType, EventDateTime, UserName, SchemaName, ObjectName, SqlStatement, EventData)
    SELECT
        @EventType,
        GETDATE(),
        SYSTEM_USER,
        SCHEMA_NAME(),
        OBJECT_NAME(@@PROCID),
        @SqlStatement,
        @Data;
END;
GO

-- Create Trigger to Audit Subject Table Data Changes
CREATE TRIGGER AuditDataChanges_Subject
ON dbo.Subject
AFTER INSERT, UPDATE, DELETE
AS 
BEGIN
    SET NOCOUNT ON;

    DECLARE @EventType NVARCHAR(50);
    DECLARE @Data XML;
    DECLARE @SqlStatement NVARCHAR(MAX) = N'';

    -- Determine the type of DML operation that invoked the trigger
	IF EXISTS (SELECT * FROM inserted)
    BEGIN
        IF EXISTS (SELECT * FROM deleted)
        BEGIN
			SET @EventType = 'UPDATE';
            SET @Data = (SELECT * FROM (
						SELECT 'inserted' AS [@Action], * FROM inserted
						UNION ALL
						SELECT 'deleted' AS [@Action], * FROM deleted
						) AS Changes
						FOR XML PATH('row'), ELEMENTS XSINIL, TYPE
        );
        END
        ELSE
        BEGIN
            SET @EventType = 'INSERT';
			SET @Data = (SELECT 'inserted' AS [@Action], * FROM inserted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
        END
    END
    ELSE
    BEGIN
        SET @EventType = 'DELETE';
		SET @Data = (SELECT 'deleted' AS [@Action], * FROM deleted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
    END

	SET @SqlStatement = 'DML operation ' + @EventType + ' performed on Subject table';

    -- Insert a log entry into the AuditLog table
    INSERT INTO dbo.AuditLog (EventType, EventDateTime, UserName, SchemaName, ObjectName, SqlStatement, EventData)
    SELECT 
        @EventType,
        GETDATE(),
        SYSTEM_USER,
        SCHEMA_NAME(),
        OBJECT_NAME(@@PROCID),
        @SqlStatement,
        @Data
END;
GO

-- Create Trigger to Audit Result Table Data Changes
CREATE TRIGGER AuditDataChanges_Result
ON dbo.Result
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @EventType NVARCHAR(50);
    DECLARE @Data XML;
    DECLARE @SqlStatement NVARCHAR(MAX) = N'';

    -- Determine the type of DML operation that invoked the trigger
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        IF EXISTS (SELECT * FROM deleted)
        BEGIN
			SET @EventType = 'UPDATE';
            SET @Data = (SELECT * FROM (
						SELECT 'inserted' AS [@Action], * FROM inserted
						UNION ALL
						SELECT 'deleted' AS [@Action], * FROM deleted
						) AS Changes
						FOR XML PATH('row'), ELEMENTS XSINIL, TYPE
        );
        END
        ELSE
        BEGIN
            SET @EventType = 'INSERT';
            -- Capture inserted data for INSERT
            SET @Data = (SELECT 'inserted' AS [Action], * FROM inserted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
        END
    END
    ELSE
    BEGIN
        SET @EventType = 'DELETE';
        -- Capture deleted data for DELETE
        SET @Data = (SELECT 'deleted' AS [@Action], * FROM deleted FOR XML PATH('row'), ELEMENTS XSINIL, TYPE);
    END

    SET @SqlStatement = 'DML operation ' + @EventType + ' performed on Student table';

    -- Insert a log entry into the AuditLog table
    INSERT INTO dbo.AuditLog (EventType, EventDateTime, UserName, SchemaName, ObjectName, SqlStatement, EventData)
    SELECT
        @EventType,
        GETDATE(),
        SYSTEM_USER,
        SCHEMA_NAME(),
        OBJECT_NAME(@@PROCID),
        @SqlStatement,
        @Data;
END;
GO

-- Create Trigger to Audit Stuctural Changes
CREATE TRIGGER AuditStructuralChanges
ON DATABASE
FOR CREATE_TABLE, ALTER_TABLE, DROP_TABLE,
    CREATE_PROCEDURE, ALTER_PROCEDURE, DROP_PROCEDURE,
    CREATE_VIEW, ALTER_VIEW, DROP_VIEW,
    CREATE_FUNCTION, ALTER_FUNCTION, DROP_FUNCTION
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @EventData XML = EVENTDATA();
    DECLARE @SqlStatement NVARCHAR(MAX) = @EventData.value('(/EVENT_INSTANCE/TSQLCommand)[1]', 'NVARCHAR(MAX)');
    DECLARE @EventType NVARCHAR(100) = @EventData.value('(/EVENT_INSTANCE/EventType)[1]', 'NVARCHAR(100)');
    DECLARE @ObjectName NVARCHAR(128) = @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]', 'NVARCHAR(128)');
    DECLARE @SchemaName NVARCHAR(128) = @EventData.value('(/EVENT_INSTANCE/SchemaName)[1]', 'NVARCHAR(128)');

    INSERT INTO dbo.AuditLog (EventType, EventDateTime, UserName, SchemaName, ObjectName, SqlStatement, EventData)
    VALUES
    (
        @EventType,
        GETDATE(),
        SYSTEM_USER,
        @SchemaName,
        @ObjectName,
        @SqlStatement,
        @EventData
    );
END;
GO

-- Create Trigger to Audit Permission Changes
CREATE TRIGGER AuditPermissionChanges
ON DATABASE
FOR GRANT_DATABASE, DENY_DATABASE, REVOKE_DATABASE, ADD_ROLE_MEMBER, DROP_ROLE_MEMBER
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @EventData XML = EVENTDATA();
    DECLARE @SqlStatement NVARCHAR(MAX) = @EventData.value('(/EVENT_INSTANCE/TSQLCommand)[1]', 'NVARCHAR(MAX)');
    DECLARE @EventType NVARCHAR(100) = @EventData.value('(/EVENT_INSTANCE/EventType)[1]', 'NVARCHAR(100)');
    DECLARE @ObjectName NVARCHAR(128) = @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]', 'NVARCHAR(128)');
    DECLARE @SchemaName NVARCHAR(128) = @EventData.value('(/EVENT_INSTANCE/SchemaName)[1]', 'NVARCHAR(128)');
    DECLARE @PrincipalName NVARCHAR(128) = @EventData.value('(/EVENT_INSTANCE/PrincipalName)[1]', 'NVARCHAR(128)');

    INSERT INTO dbo.AuditLog (EventType, EventDateTime, UserName, SchemaName, ObjectName, SqlStatement, EventData)
    VALUES
    (
        @EventType,
        GETDATE(),
        SYSTEM_USER,
        @SchemaName,
        @ObjectName,
        @SqlStatement,
        @EventData
    );
END;
GO

-- Auditing for login and logout
-- Create Table to store login history
CREATE TABLE LoginHistory (
    ID INT IDENTITY(1,1) PRIMARY KEY,
    UserID NVARCHAR(100),
    LoginTime DATETIME,
    LogoutTime DATETIME NULL, -- Initially NULL, to be updated on logout
    Succeeded BIT -- 1 for successful login, 0 for failed login
);

-- Procedure to record login time
CREATE PROCEDURE dbo.RecordLogin
    @Succeeded BIT
AS
BEGIN
    DECLARE @UserID NVARCHAR(100);
    DECLARE @LoginName NVARCHAR(100) = ORIGINAL_LOGIN();
    
    -- Try to get the student ID
    SELECT TOP 1 @UserID = ID
    FROM dbo.Student
    WHERE ID = @LoginName;

    -- If not found, try to get the lecturer ID
    IF @UserID IS NULL
    BEGIN
        SELECT TOP 1 @UserID = ID
        FROM dbo.Lecturer
        WHERE ID = @LoginName;
    END

    -- If a match is found in either table, record the login
    IF @UserID IS NOT NULL
    BEGIN
        INSERT INTO LoginHistory (UserID, LoginTime, Succeeded)
        VALUES (@UserID, GETDATE(), @Succeeded);
    END
END;
GO

-- Procedure to record logout time
CREATE PROCEDURE dbo.RecordLogout
AS
BEGIN
    DECLARE @UserID NVARCHAR(100);
    DECLARE @LoginName NVARCHAR(100) = ORIGINAL_LOGIN();
    DECLARE @HistoryID INT;

    -- Try to get the student ID
    SELECT TOP 1 @UserID = ID
    FROM dbo.Student
    WHERE ID = @LoginName;

    -- If not found, try to get the lecturer ID
    IF @UserID IS NULL
    BEGIN
        SELECT TOP 1 @UserID = ID
        FROM dbo.Lecturer
        WHERE ID = @LoginName;
    END

    -- If a user ID is found, update the logout time for the most recent login record
    IF @UserID IS NOT NULL
    BEGIN
        SELECT TOP 1 @HistoryID = ID
        FROM LoginHistory
        WHERE UserID = @UserID AND LogoutTime IS NULL
        ORDER BY LoginTime DESC;

        -- Update the LogoutTime for the identified record
        IF @HistoryID IS NOT NULL
        BEGIN
            UPDATE LoginHistory
            SET LogoutTime = GETDATE()
            WHERE ID = @HistoryID;
        END
    END
END;
GO

-- Procedure to generate login & logout report for DBAdmins
CREATE PROCEDURE dbo.GenerateLoginLogoutReport
AS
BEGIN
    IF IS_MEMBER('DBAdmins') = 1 OR IS_SRVROLEMEMBER('sysadmin') = 1
    BEGIN
        SELECT *
        FROM LoginHistory
        WHERE CAST(LoginTime AS DATE) = CAST(GETDATE() AS DATE);
    END
    ELSE
    BEGIN
        THROW 50000, 'You do not have permission to generate the report.', 1;
    END
END;
GO

-- Create roles for DB Admins, Students, and Lecturers
CREATE ROLE DBAdmins;
CREATE ROLE Students;
CREATE ROLE Lecturers;

-- DBAdmins Permissions
-- Grant privileges to DBAdmins
-- Create schema for dbadmins
CREATE SCHEMA DBAdminsSchema;
GRANT ALTER ON SCHEMA::DBAdminsSchema TO DBAdmins;

GRANT ALTER ANY USER TO DBAdmins;
GRANT ALTER ON ROLE::Students TO DBAdmins;
GRANT ALTER ON ROLE::Lecturers TO DBAdmins;
GO

-- Create View for students and lecturers tables except for password
CREATE VIEW dbo.StudentInfo AS
SELECT ID, Name, Phone
FROM dbo.Student;
GO

CREATE VIEW dbo.LecturerInfo AS
SELECT ID, Name, Phone, Department
FROM dbo.Lecturer;
GO

-- Grant DBAdmins on the view created
GRANT SELECT, INSERT, UPDATE ON dbo.StudentInfo TO DBAdmins;
GRANT SELECT, INSERT, UPDATE ON dbo.LecturerInfo TO DBAdmins;
GO

-- Deny DBAdmins on the base table
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Student TO DBAdmins;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Lecturer TO DBAdmins;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Result TO DBAdmins;
GO

-- Students Permissions
-- Grant SELECT and UPDATE on their own details. This is controlled by the row-level security policy.
GRANT SELECT, UPDATE ON dbo.Student TO Students;
GO

-- Create the row-level security policy function.
CREATE FUNCTION dbo.fn_securitypredicate_Student(@StudentID AS VARCHAR(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS result
WHERE @StudentID = CAST(SYSTEM_USER AS VARCHAR(6));
GO

-- Apply the row-level security policy to the Student table.
CREATE SECURITY POLICY StudentRowLevelSecurity
ADD FILTER PREDICATE dbo.fn_securitypredicate_Student(ID) ON dbo.Student
WITH (STATE = ON);
GO

-- Create a view that students can use to see their academic data.
CREATE VIEW dbo.StudentAcademicData AS
SELECT s.ID, s.Name, s.Phone, r.SubjectCode, r.AssessmentDate, r.Grade
FROM dbo.Student s
JOIN dbo.Result r ON s.ID = r.StudentID
WHERE s.ID = CAST(SYSTEM_USER AS VARCHAR(6));
GO

-- Grant the necessary permissions on the view to the Students role.
GRANT SELECT ON dbo.StudentAcademicData TO Students;
GO

-- Lecturers Permissions
-- Grant SELECT and UPDATE on their own details. This is controlled by the row-level security policy.
GRANT SELECT, UPDATE ON dbo.Lecturer TO Lecturers;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.Subject TO Lecturers;
GO

-- Create a function for row-level security on Lecturer table.
CREATE FUNCTION dbo.fn_securitypredicate_Lecturer(@ID AS VARCHAR(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS predicate_result
WHERE @ID = CAST(SYSTEM_USER AS VARCHAR(6));
GO

-- Create a security policy for row-level security on the Lecturer table.
CREATE SECURITY POLICY LecturerRowLevelSecurity
ADD FILTER PREDICATE dbo.fn_securitypredicate_Lecturer(ID) ON dbo.Lecturer
WITH (STATE = ON);
GO

-- Create a view to view all students’ details.
CREATE VIEW dbo.AllStudentsInfo AS
SELECT ID, Name, Phone
FROM dbo.Student;
GO

-- Grant SELECT on the view to Lecturers.
GRANT SELECT ON dbo.AllStudentsInfo TO Lecturers;
GO

-- Create a view to view all marks entered by lecturers from the same department.
CREATE VIEW dbo.DepartmentResults AS
SELECT s.ID AS StudentID, s.Name AS StudentName, s.Phone AS StudentPhone, r.SubjectCode, r.AssessmentDate, r.Grade
FROM dbo.Result r
JOIN dbo.Student s ON r.StudentID = s.ID
JOIN dbo.Lecturer l ON r.LecturerID = l.ID
WHERE l.Department IN (SELECT Department FROM dbo.Lecturer WHERE ID = SYSTEM_USER);
GO

ALTER VIEW dbo.DepartmentResults AS
SELECT r.ID AS ResultID, r.StudentID, r.LecturerID, s.Name AS StudentName, s.Phone AS StudentPhone, r.SubjectCode, r.AssessmentDate, r.Grade, r.CreatedBy, r.Department
FROM dbo.Result r
JOIN dbo.Student s ON r.StudentID = s.ID
WHERE r.Department = (SELECT Department FROM dbo.Lecturer WHERE ID = SYSTEM_USER);
GO

-- Grant SELECT on the department results view to Lecturers.
GRANT SELECT ON dbo.DepartmentResults TO Lecturers;
GO

-- Grant permissions to add new academic data (Result Table).
GRANT INSERT ON dbo.Result TO Lecturers;
GO

-- Create Table Associate Lecturers with Subjects
CREATE TABLE LecturerSubjects (
    LecturerID varchar(6) REFERENCES Lecturer(ID),
    SubjectCode varchar(7) REFERENCES Subject(Code),
    PRIMARY KEY (LecturerID, SubjectCode)
);

-- Create Stored Procedure to Add New Academic Data
ALTER PROCEDURE AddResult
    @StudentID varchar(6),
    @LecturerID varchar(6),
    @SubjectCode varchar(7),
    @Grade varchar(2),
    @CreatedBy varchar(6),
    @Department varchar(30)
AS
BEGIN
	DECLARE @CurrentLecturerID varchar(6);
    SELECT @CurrentLecturerID = ID FROM Lecturer WHERE ID = SYSTEM_USER;

    IF @CurrentLecturerID <> @LecturerID
    BEGIN
        RAISERROR('You are not authorized to add results for other lecturers', 16, 1);
        RETURN;
    END
    -- Check if the lecturer is allowed to add results for this subject
    IF EXISTS(SELECT 1 FROM LecturerSubjects WHERE LecturerID = @LecturerID AND SubjectCode = @SubjectCode)
    BEGIN
        -- Insert the result if the lecturer is associated with the subject
        INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade, CreatedBy, Department)
        VALUES (@StudentID, @LecturerID, @SubjectCode, GETDATE(), @Grade, @CreatedBy, @Department)
    END
    ELSE
    BEGIN
        -- Otherwise, throw an error or handle the unauthorized attempt
        RAISERROR ('Lecturer is not authorized to add results for this subject', 16, 1)
    END
END
GO

-- Create Trigger to check if the lecturer teach that subject
ALTER TRIGGER trg_CheckLecturerSubject
ON Result
AFTER INSERT, UPDATE
AS
BEGIN
    DECLARE @LecturerID varchar(6);
    DECLARE @SubjectCode varchar(7);
	DECLARE @CurrentLecturerID varchar(6);

    SELECT @LecturerID = LecturerID, @SubjectCode = SubjectCode
    FROM inserted;
	SELECT @CurrentLecturerID = ID FROM Lecturer WHERE ID = SYSTEM_USER;

    IF @CurrentLecturerID <> @LecturerID
    BEGIN
        RAISERROR('You are not authorized to add results for other lecturers', 16, 1);
        ROLLBACK TRANSACTION;
		RETURN;
    END
END
GO

-- Grant and revoke the lecturer permission
GRANT EXECUTE ON AddResult TO Lecturers;
REVOKE INSERT ON dbo.Result FROM Lecturers;

-- Granting INSERT, UPDATE, and DELETE permissions to Lecturers on the Result table.
-- The actual enforcement of these actions to their own records will be handled through stored procedures.
GRANT INSERT, UPDATE, DELETE ON dbo.Result TO Lecturers;
GO

-- Creating a procedure to handle updates, ensuring only own records can be updated
CREATE PROCEDURE UpdateResult
    @ResultID INT,
    @Grade VARCHAR(2),
    @LecturerID VARCHAR(6) -- The ID of the lecturer making the update
AS
BEGIN
    -- Only allow update if the lecturer is the one who created the record
    UPDATE dbo.Result
    SET Grade = @Grade
    WHERE ID = @ResultID AND CreatedBy = @LecturerID;
END;
GO

-- Creating a procedure to handle deletes, ensuring only own records can be deleted
CREATE PROCEDURE DeleteResult
    @ResultID INT,
    @LecturerID VARCHAR(6) -- The ID of the lecturer making the delete
AS
BEGIN
    -- Only allow delete if the lecturer is the one who created the record
    DELETE FROM dbo.Result
    WHERE ID = @ResultID AND CreatedBy = @LecturerID;
END;
GO

-- Revoke direct update and delete on Result table from Lecturers role.
REVOKE UPDATE, DELETE ON dbo.Result FROM Lecturers;
GRANT EXECUTE ON UpdateResult TO Lecturers;
GRANT EXECUTE ON DeleteResult TO Lecturers;
GO

-- Creating Encryption Certificate for password encryption
USE AIS;
GO

-- Create a Master Key
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Xs3#v8S@pWqz!';
GO

-- Create a Certificate
CREATE CERTIFICATE AISServerCert WITH SUBJECT = 'AIS Certificate';
GO

-- Create a Symmetric Key
CREATE SYMMETRIC KEY PasswordEncryptionKey
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE AISServerCert;
GO

-- Stored Procedure automatically encrypt password when created new user.
-- Stored Procedure for adding Student
CREATE PROCEDURE dbo.AddNewStudent
    @StudentID VARCHAR(6),
    @TempPassword VARCHAR(100),
    @Name VARCHAR(100),
    @Phone VARCHAR(20)
AS
BEGIN
    OPEN SYMMETRIC KEY PasswordEncryptionKey
    DECRYPTION BY CERTIFICATE AISServerCert;

    INSERT INTO dbo.Student (ID, SystemPwd, Name, Phone)
    VALUES (
        @StudentID, 
        EncryptByKey(Key_GUID('PasswordEncryptionKey'), @TempPassword),
        @Name, 
        @Phone
    );

    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
END;
GO

CREATE PROCEDURE dbo.AddNewLecturer
    @LecturerID VARCHAR(6),
    @TempPassword VARCHAR(100),
    @Name VARCHAR(100),
    @Phone VARCHAR(20),
    @Department VARCHAR(30)
AS
BEGIN
    OPEN SYMMETRIC KEY PasswordEncryptionKey
    DECRYPTION BY CERTIFICATE AISServerCert;

    INSERT INTO dbo.Lecturer (ID, SystemPwd, Name, Phone, Department)
    VALUES (
        @LecturerID, 
        EncryptByKey(Key_GUID('PasswordEncryptionKey'), @TempPassword),
        @Name, 
        @Phone,
        @Department
    );

    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
END;
GO

-- Grant the EXECUTE permission to DB Admins
GRANT EXECUTE ON dbo.AddNewStudent TO DBAdmins;
GRANT EXECUTE ON dbo.AddNewLecturer TO DBAdmins;
GO

CREATE PROCEDURE dbo.UpdateStudentDetails
    @StudentID VARCHAR(6),
    @NewPassword VARCHAR(100),
    @NewName VARCHAR(100),
    @NewPhone VARCHAR(20)
AS
BEGIN
    -- Verify the executing user is the student whose details are being changed
    IF SYSTEM_USER = @StudentID
    BEGIN
        -- Open the symmetric key
        OPEN SYMMETRIC KEY PasswordEncryptionKey
        DECRYPTION BY CERTIFICATE AISServerCert;

        -- Update the student's password, name, and phone number
        UPDATE dbo.Student
        SET SystemPwd = EncryptByKey(Key_GUID('PasswordEncryptionKey'), @NewPassword),
            Name = @NewName,
            Phone = @NewPhone
        WHERE ID = @StudentID;

        -- Close the symmetric key
        CLOSE SYMMETRIC KEY PasswordEncryptionKey;
    END
    ELSE
    BEGIN
        -- Optionally handle the error case where the user does not have permission to update the record
        THROW 50001, 'You do not have permission to change these details.', 1;
    END
END;
GO

-- Grant the EXECUTE permission to students for this stored procedure
GRANT EXECUTE ON dbo.UpdateStudentDetails TO Students;
GO

-- Revoke direct UPDATE permission on the Student table from the Students role
REVOKE UPDATE ON dbo.Student FROM Students;
GO

-- Lecturers to update their details.
CREATE PROCEDURE dbo.UpdateLecturerDetails
    @LecturerID VARCHAR(6),
	@NewPassword VARCHAR(100),
    @NewName VARCHAR(100),
    @NewPhone VARCHAR(20),
    @NewDepartment VARCHAR(30)
AS
BEGIN
    -- Verify the executing user is the lecturer whose details are being changed
    IF SYSTEM_USER = @LecturerID
    BEGIN
		-- Open the symmetric key
        OPEN SYMMETRIC KEY PasswordEncryptionKey
        DECRYPTION BY CERTIFICATE AISServerCert;

        -- Update the lecturer's password, name, phone number, and department
        UPDATE dbo.Lecturer
        SET SystemPwd = EncryptByKey(Key_GUID('PasswordEncryptionKey'), @NewPassword),
			Name = @NewName,
            Phone = @NewPhone,
            Department = @NewDepartment
        WHERE ID = @LecturerID;

		-- Close the symmetric key
        CLOSE SYMMETRIC KEY PasswordEncryptionKey;
    END
    ELSE
    BEGIN
        -- Optionally handle the error case where the user does not have permission to update the record
        THROW 50001, 'You do not have permission to change these details.', 1;
    END
END;
GO

-- Grant the EXECUTE permission to lecturers for this stored procedure
GRANT EXECUTE ON dbo.UpdateLecturerDetails TO Lecturers;
GO

-- Revoke direct UPDATE permission on the Lecturer table from the Lecturers role
REVOKE UPDATE ON dbo.Lecturer FROM Lecturers;
GO

-- Create a Database Encryption Key (DEK) for TDE, protected by the certificate
USE master;
GO
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MzF!0B$r3H6v&dK';
GO

-- Create a new certificate for TDE
CREATE CERTIFICATE TDEAISCertificate WITH SUBJECT = 'TDE AIS Certificate';
GO

USE AIS;
GO

-- Create a database encryption key (DEK) using the certificate from the master database
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDEAISCertificate;
GO

-- Enable TDE on your AIS database
ALTER DATABASE AIS
SET ENCRYPTION ON;
GO

-- Backup TDE
USE master;
GO

BACKUP CERTIFICATE TDEAISCertificate TO FILE = 'C:\APU\APU Degree Level 3\Sem 2\Database Security\AIS_Database\SQL_Backups\TDE_Backup\TDEAISCertificateBackup'
WITH PRIVATE KEY (
    FILE = 'C:\APU\APU Degree Level 3\Sem 2\Database Security\AIS_Database\SQL_Backups\TDE_Backup\TDEAISCertificatePrivateKey',
    ENCRYPTION BY PASSWORD = '7g@W5#hN!QpL8^J'
);
GO

-- Backup Password Encryption
USE AIS;
GO

BACKUP CERTIFICATE AISServerCert TO FILE = 'C:\APU\APU Degree Level 3\Sem 2\Database Security\AIS_Database\SQL_Backups\Pwd_Encryption_Backup\AISServerCertBackup'
WITH PRIVATE KEY (
    FILE = 'C:\APU\APU Degree Level 3\Sem 2\Database Security\AIS_Database\SQL_Backups\Pwd_Encryption_Backup\AISServerCertPrivateKey',
    ENCRYPTION BY PASSWORD = 'Y#8mCz!7$X3pLbQ'
);
GO

-- Automated Backup every 6 hours
USE msdb ;
GO

-- Create a new job named 'Automated_Backup'
EXEC dbo.sp_add_job
    @job_name = N'Automated_Backup' ;
GO

-- Add a step named 'Backup_Database' to the job
EXEC sp_add_jobstep
    @job_name = N'Automated_Backup',
    @step_name = N'Backup_Database',
    @subsystem = N'TSQL',
    @command = N'BACKUP DATABASE AIS TO DISK = N''C:\APU\APU Degree Level 3\Sem 2\Database Security\AIS_Database\SQL_Backups\Database Backup\AIS.bak'' WITH NOFORMAT, NOINIT, NAME = N''AIS-Full Database Backup'', SKIP, NOREWIND, NOUNLOAD, STATS = 10', 
    @retry_attempts = 5,
    @retry_interval = 5 ;
GO

-- Schedule the job to run every 6 hours
EXEC dbo.sp_add_schedule
    @schedule_name = N'Every_6_Hours',
    @freq_type = 8,
    @freq_interval = 1,
    @freq_recurrence_factor = 1,
    @freq_subday_type = 8,
    @freq_subday_interval = 6,
    @active_start_time = 000000;
GO

SELECT schedule_id, name 
FROM msdb.dbo.sysschedules
WHERE name = N'Every_6_Hours';

EXEC dbo.sp_update_schedule
    @schedule_id = '9',
    @freq_type = 4, -- Daily
    @freq_interval = 1, -- Every day
    @freq_subday_type = 8, -- Hours
    @freq_subday_interval = 6, -- Every 6 hours
    @active_start_time = 000000; -- Starting at midnight
GO

-- Attach the schedule to the job
EXEC sp_attach_schedule
   @job_name = N'Automated_Backup',
   @schedule_name = N'Every_6_Hours' ;
GO

-- Make the job start when the SQL Server Agent starts
EXEC dbo.sp_update_job
    @job_name = N'Automated_Backup',
    @enabled = 1,
    @start_step_id = 1,
    @delete_level = 0;
GO

-- Add the job to the SQL Server Agent
EXEC dbo.sp_add_jobserver
    @job_name = N'Automated_Backup' ;
GO

-- Modifying AIS Database
USE AIS;
GO
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::DBAdminsSchema TO DBAdmins WITH GRANT OPTION;
GRANT CONTROL ON SCHEMA::DBAdminsSchema TO DBAdmins WITH GRANT OPTION;

GRANT CONTROL ON SYMMETRIC KEY::PasswordEncryptionKey TO DBAdmins;
GRANT CONTROL ON CERTIFICATE::AISServerCert TO DBAdmins;

GRANT CONTROL ON SYMMETRIC KEY::PasswordEncryptionKey TO Students;
GRANT CONTROL ON CERTIFICATE::AISServerCert TO Students;

GRANT CONTROL ON SYMMETRIC KEY::PasswordEncryptionKey TO Lecturers;
GRANT CONTROL ON CERTIFICATE::AISServerCert TO Lecturers;

GRANT EXEC ON dbo.GenerateLoginLogoutReport TO DBAdmins;
GRANT SELECT, Insert ON AuditLog TO DBAdmins;
GRANT EXECUTE ON dbo.RecordLogin TO Students, Lecturers;
GRANT EXECUTE ON dbo.RecordLogout TO Students, Lecturers;

DENY SELECT ON dbo.Student TO Students;
DENY SELECT ON dbo.Lecturer TO Lecturers;

-- Procedure for Students and Lecturers to view own details
ALTER PROCEDURE dbo.ViewOwnDetails
AS
BEGIN
    DECLARE @UserID VARCHAR(6) = CAST(SYSTEM_USER AS VARCHAR(6));
    DECLARE @UserRole NVARCHAR(128);
    
    -- Determine the role of the user
    SELECT @UserRole = CASE
        WHEN EXISTS (SELECT * FROM dbo.Student WHERE ID = @UserID) THEN 'Student'
        WHEN EXISTS (SELECT * FROM dbo.Lecturer WHERE ID = @UserID) THEN 'Lecturer'
        ELSE NULL
    END;
    
    -- Open the symmetric key
    OPEN SYMMETRIC KEY PasswordEncryptionKey
    DECRYPTION BY CERTIFICATE AISServerCert;
    
    IF @UserRole = 'Student'
    BEGIN
        -- Return details for student
        SELECT 
            ID, 
            Name, 
			CONVERT(VARCHAR, DECRYPTBYKEY(SystemPwd)) AS LoginPassword,
            Phone
        FROM 
            dbo.Student
        WHERE 
            ID = @UserID;
    END
    ELSE IF @UserRole = 'Lecturer'
    BEGIN
        -- Return details for lecturer
        SELECT 
            ID, 
            Name, 
			CONVERT(VARCHAR, DECRYPTBYKEY(SystemPwd)) AS LoginPassword,
            Phone,
            Department
        FROM 
            dbo.Lecturer
        WHERE 
            ID = @UserID;
    END
    
    -- Close the symmetric key
    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
    
    -- If @UserRole is NULL, then the user does not exist in either table
    IF @UserRole IS NULL
    BEGIN
        THROW 50001, 'User does not exist in the system or does not have permission to view details.', 1;
    END
END;
GO

GRANT EXECUTE ON ViewOwnDetails TO Students, Lecturers;

-- Drop the security policy's association with the function
ALTER SECURITY POLICY StudentRowLevelSecurity
DROP FILTER PREDICATE ON dbo.Student;

-- Alter the function
ALTER FUNCTION dbo.fn_securitypredicate_Student(@StudentID AS VARCHAR(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS result
WHERE @StudentID = CAST(SYSTEM_USER AS VARCHAR(6))
   OR IS_SRVROLEMEMBER('sysadmin') = 1
   OR IS_ROLEMEMBER('DBAdmins') = 1
   OR IS_ROLEMEMBER('Lecturers') = 1;
GO

-- Re-apply the function to the security policy
ALTER SECURITY POLICY StudentRowLevelSecurity
ADD FILTER PREDICATE dbo.fn_securitypredicate_Student(ID) ON dbo.Student;
GO

-- Drop the security policy's association with the function
ALTER SECURITY POLICY LecturerRowLevelSecurity
DROP FILTER PREDICATE ON dbo.Lecturer;

-- Alter the function
ALTER FUNCTION dbo.fn_securitypredicate_Lecturer(@ID AS VARCHAR(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS result
WHERE @ID = CAST(SYSTEM_USER AS VARCHAR(6))
   OR IS_SRVROLEMEMBER('sysadmin') = 1
   OR IS_ROLEMEMBER('DBAdmins') = 1;
GO

-- Re-apply the function to the security policy
ALTER SECURITY POLICY LecturerRowLevelSecurity
ADD FILTER PREDICATE dbo.fn_securitypredicate_Lecturer(ID) ON dbo.Lecturer
GO


-- Testing
-- Create DBAdmins
USE master;
GO
CREATE LOGIN DBAdminLogin WITH PASSWORD = 'DBAdmin@1234';
USE AIS;
GO
CREATE USER AISAdmin FOR LOGIN DBAdminLogin;
ALTER ROLE DBAdmins ADD MEMBER AISAdmin;
GRANT ALTER ANY LOGIN TO DBAdminLogin;

-- Populating Lecturer Subject Table
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1001', 'CS101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1001', 'CS102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1001', 'CS103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1002', 'CYB101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1002', 'CYB102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1002', 'CYB103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1003', 'SE101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1003', 'SE102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1003', 'SE103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1004', 'AI101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1004', 'AI102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1004', 'AI103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1005', 'DS101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1005', 'DS102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1005', 'DS103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1006', 'IT101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1006', 'IT102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1006', 'IT103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1007', 'CS101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1007', 'CS102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1007', 'CS103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1008', 'CYB101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1008', 'CYB102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1008', 'CYB103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1009', 'SE101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1009', 'SE102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1009', 'SE103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1010', 'AI101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1010', 'AI102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1010', 'AI103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1011', 'DS101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1011', 'DS102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1011', 'DS103');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1012', 'IT101');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1012', 'IT102');
INSERT INTO LecturerSubjects (LecturerID, SubjectCode) VALUES ('LC1012', 'IT103');





-- Testting Enviroment
-- Execute as DBAdmin
EXECUTE AS LOGIN = 'DBAdminLogin';
SELECT SUSER_NAME() AS CurrentUser;

-- Generate Login and Logout Report
EXEC dbo.GenerateLoginLogoutReport

-- Check Audit Log
SELECT * FROM AuditLog

-- Select for structural change
SELECT *
FROM AuditLog
WHERE EventType IN ('CREATE_TABLE', 'ALTER_TABLE', 'DROP_TABLE', 
					'CREATE_PROCEDURE', 'ALTER_PROCEDURE', 'DROP_PROCEDURE', 
					'CREATE_VIEW', 'ALTER_VIEW', 'DROP_VIEW', 
					'CREATE_FUNCTION', 'ALTER_FUNCTION', 'DROP_FUNCTION');

-- Select for data change
SELECT *
FROM AuditLog
WHERE EventType IN ('INSERT', 'UPDATE', 'DELETE');

-- Select for permission change
SELECT *
FROM AuditLog
WHERE EventType IN ('GRANT_DATABASE', 'DENY_DATABASE', 'REVOKE_DATABASE', 
					'ADD_ROLE_MEMBER', 'DROP_ROLE_MEMBER');

-- Students Role
SELECT * FROM StudentInfo

-- Create some Student role from DBAdmins
EXEC dbo.AddNewStudent @StudentID = 'ST1001', @TempPassword = 'ST1001@1234', @Name = 'John Doe', @Phone = '012-2148759';
EXEC dbo.AddNewStudent @StudentID = 'ST1002', @TempPassword = 'ST1002@1234', @Name = 'Aaron Chia', @Phone = '011-21512548';
EXEC dbo.AddNewStudent @StudentID = 'ST1003', @TempPassword = 'ST1003@1234', @Name = 'Micheal Tan', @Phone = '018-8549876';
EXEC dbo.AddNewStudent @StudentID = 'ST1004', @TempPassword = 'ST1004@1234', @Name = 'Stainly', @Phone = '012-5486219';
EXEC dbo.AddNewStudent @StudentID = 'ST1005', @TempPassword = 'ST1005@1234', @Name = 'Katty', @Phone = '018-4251987';
EXEC dbo.AddNewStudent @StudentID = 'ST1006', @TempPassword = 'ST1006@1234', @Name = 'Peter Park', @Phone = '012-3521687';
EXEC dbo.AddNewStudent @StudentID = 'ST1007', @TempPassword = 'ST1007@1234', @Name = 'Lucas Green', @Phone = '012-9966587';
EXEC dbo.AddNewStudent @StudentID = 'ST1008', @TempPassword = 'ST1008@1234', @Name = 'Emma Wilson', @Phone = '011-55698874';
EXEC dbo.AddNewStudent @StudentID = 'ST1009', @TempPassword = 'ST1009@1234', @Name = 'Idris Elba', @Phone = '018-5488795';
EXEC dbo.AddNewStudent @StudentID = 'ST1010', @TempPassword = 'ST1010@1234', @Name = 'Nora Khan', @Phone = '012-3322687';
EXEC dbo.AddNewStudent @StudentID = 'ST1011', @TempPassword = 'ST1011@1234', @Name = 'Henry Adams', @Phone = '018-1548779';
EXEC dbo.AddNewStudent @StudentID = 'ST1012', @TempPassword = 'ST1012@1234', @Name = 'Sophia Turner', @Phone = '012-6599887';

-- Create Student Login
CREATE LOGIN ST1001 WITH PASSWORD = 'ST1001@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1002 WITH PASSWORD = 'ST1002@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1003 WITH PASSWORD = 'ST1003@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1004 WITH PASSWORD = 'ST1004@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1005 WITH PASSWORD = 'ST1005@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1006 WITH PASSWORD = 'ST1006@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1007 WITH PASSWORD = 'ST1007@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1008 WITH PASSWORD = 'ST1008@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1009 WITH PASSWORD = 'ST1009@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1010 WITH PASSWORD = 'ST1010@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1011 WITH PASSWORD = 'ST1011@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN ST1012 WITH PASSWORD = 'ST1012@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
GO

-- Create User for Students access
CREATE USER JohnDoe for LOGIN ST1001;
GO
ALTER ROLE Students ADD MEMBER JohnDoe;
GO

CREATE USER AaronChia for LOGIN ST1002;
GO
ALTER ROLE Students ADD MEMBER AaronChia;
GO

CREATE USER MichealTan for LOGIN ST1003;
GO
ALTER ROLE Students ADD MEMBER MichealTan;
GO

CREATE USER Stainly for LOGIN ST1004;
GO
ALTER ROLE Students ADD MEMBER Stainly;
GO

CREATE USER Katty for LOGIN ST1005;
GO
ALTER ROLE Students ADD MEMBER Katty;
GO

CREATE USER PeterPark for LOGIN ST1006;
GO
ALTER ROLE Students ADD MEMBER PeterPark;
GO

CREATE USER LucasGreen for LOGIN ST1007;
GO
ALTER ROLE Students ADD MEMBER LucasGreen;
GO

CREATE USER EmmaWilson for LOGIN ST1008;
GO
ALTER ROLE Students ADD MEMBER EmmaWilson;
GO

CREATE USER IdrisElba for LOGIN ST1009;
GO
ALTER ROLE Students ADD MEMBER IdrisElba;
GO

CREATE USER NoraKhan for LOGIN ST1010;
GO
ALTER ROLE Students ADD MEMBER NoraKhan;
GO

CREATE USER HenryAdams for LOGIN ST1011;
GO
ALTER ROLE Students ADD MEMBER HenryAdams;
GO

CREATE USER SophiaTurner for LOGIN ST1012;
GO
ALTER ROLE Students ADD MEMBER SophiaTurner;
GO

-- Lecturers Role
SELECT * FROM LecturerInfo

-- Create some Lecturer role from DBAdmins
EXEC dbo.AddNewLecturer @LecturerID = 'LC1001', @TempPassword = 'LC1001@1234', @Name = 'Alice Smith', @Phone = '012-1158764', @Department = 'Computer Science';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1002', @TempPassword = 'LC1002@1234', @Name = 'Bob Johnson', @Phone = '011-23548896', @Department = 'Cybersecurity';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1003', @TempPassword = 'LC1003@1234', @Name = 'Cathy Brown', @Phone = '018-5487225', @Department = 'Software Engineering';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1004', @TempPassword = 'LC1004@1234', @Name = 'David Clark', @Phone = '012-2459987', @Department = 'Artificial Intelligence';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1005', @TempPassword = 'LC1005@1234', @Name = 'Eva Adams', @Phone = '012-5482224', @Department = 'Data Science';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1006', @TempPassword = 'LC1006@1234', @Name = 'Frank Morris', @Phone = '011-54879655', @Department = 'Information Technology';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1007', @TempPassword = 'LC1007@1234', @Name = 'Jane Miller', @Phone = '018-5487762', @Department = 'Computer Science';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1008', @TempPassword = 'LC1008@1234', @Name = 'Mike Barnes', @Phone = '018-2266547', @Department = 'Cybersecurity';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1009', @TempPassword = 'LC1009@1234', @Name = 'Susan Lee', @Phone = '011-55487996', @Department = 'Software Engineering';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1010', @TempPassword = 'LC1010@1234', @Name = 'Alan Turing', @Phone = '012-5487966', @Department = 'Artificial Intelligence';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1011', @TempPassword = 'LC1011@1234', @Name = 'Carol White', @Phone = '012-2665487', @Department = 'Data Science';
EXEC dbo.AddNewLecturer @LecturerID = 'LC1012', @TempPassword = 'LC1012@1234', @Name = 'Omar Reed', @Phone = '018-5551548', @Department = 'Information Technology';

-- Create Lecturer Login
CREATE LOGIN LC1001 WITH PASSWORD = 'LC1001@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1002 WITH PASSWORD = 'LC1002@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1003 WITH PASSWORD = 'LC1003@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1004 WITH PASSWORD = 'LC1004@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1005 WITH PASSWORD = 'LC1005@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1006 WITH PASSWORD = 'LC1006@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1007 WITH PASSWORD = 'LC1007@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1008 WITH PASSWORD = 'LC1008@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1009 WITH PASSWORD = 'LC1009@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1010 WITH PASSWORD = 'LC1010@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1011 WITH PASSWORD = 'LC1011@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
CREATE LOGIN LC1012 WITH PASSWORD = 'LC1012@1234' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
GO

-- Create User for Lecturers access
CREATE USER AliceSmith for LOGIN LC1001;
GO
ALTER ROLE Lecturers ADD MEMBER AliceSmith;
GO

CREATE USER BobJohnson for LOGIN LC1002;
GO
ALTER ROLE Lecturers ADD MEMBER BobJohnson;
GO

CREATE USER CathyBrown for LOGIN LC1003;
GO
ALTER ROLE Lecturers ADD MEMBER CathyBrown;
GO

CREATE USER DavidClark for LOGIN LC1004;
GO
ALTER ROLE Lecturers ADD MEMBER DavidClark;
GO

CREATE USER EvaAdams for LOGIN LC1005;
GO
ALTER ROLE Lecturers ADD MEMBER EvaAdams;
GO

CREATE USER FrankMorris for LOGIN LC1006;
GO
ALTER ROLE Lecturers ADD MEMBER FrankMorris;
GO

CREATE USER JaneMiller for LOGIN LC1007;
GO
ALTER ROLE Lecturers ADD MEMBER JaneMiller;
GO

CREATE USER MikeBarnes for LOGIN LC1008;
GO
ALTER ROLE Lecturers ADD MEMBER MikeBarnes;
GO

CREATE USER SusanLee for LOGIN LC1009;
GO
ALTER ROLE Lecturers ADD MEMBER SusanLee;
GO

CREATE USER AlanTuring for LOGIN LC1010;
GO
ALTER ROLE Lecturers ADD MEMBER AlanTuring;
GO

CREATE USER CarolWhite for LOGIN LC1011;
GO
ALTER ROLE Lecturers ADD MEMBER CarolWhite;
GO

CREATE USER OmarReed for LOGIN LC1012;
GO
ALTER ROLE Lecturers ADD MEMBER OmarReed;
GO

-- Test to create table within DBAdminsSchema
Create Table DBAdminsSchema.Test(
name varchar(100) primary key,
phnenumber varchar (20)
)

-- Test to create table within dbo schema
Create Table dbo.Test(
name varchar(100) primary key,
phnenumber varchar (20)
)

-- Test create view to let students view their details
ALTER VIEW DBAdminsSchema.View_StudentDetails AS
SELECT ID, Name, Phone FROM StudentInfo;

-- Test grant permission 
GRANT SELECT ON DBAdminsSchema.View_StudentDetails TO Students, Lecturers;

-- Test select from base table
SELECT * FROM dbo.Student;

REVERT;

-- Test for Lecturer LC1001 - Computer Science
EXECUTE AS LOGIN = 'LC1001';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View Own Details
EXEC dbo.ViewOwnDetails;

-- Update Own Details
EXEC dbo.UpdateLecturerDetails 
	@LecturerID = 'LC1001', 
	@NewPassword = 'Alice@1234', 
	@NewName = 'Alice Smith', 
	@NewPhone = '012-1158764', 
	@NewDepartment = 'Computer Science';

-- View students info
SELECT * FROM dbo.AllStudentsInfo

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

-- Insert data to Subject Table
-- For Computer Science
INSERT INTO Subject (Code, Title) VALUES ('CS101', 'Introduction to Computer Science');
INSERT INTO Subject (Code, Title) VALUES ('CS102', 'Data Structures and Algorithms');
INSERT INTO Subject (Code, Title) VALUES ('CS103', 'Operating Systems');
-- For Cybersecurity
INSERT INTO Subject (Code, Title) VALUES ('CYB101', 'Fundamentals of Cybersecurity');
INSERT INTO Subject (Code, Title) VALUES ('CYB102', 'Network Security');
INSERT INTO Subject (Code, Title) VALUES ('CYB103', 'Cryptography');
-- For Software Engineering
INSERT INTO Subject (Code, Title) VALUES ('SE101', 'Software Development Lifecycle');
INSERT INTO Subject (Code, Title) VALUES ('SE102', 'Object-Oriented Design');
INSERT INTO Subject (Code, Title) VALUES ('SE103', 'Agile Methodologies');
-- For Artificial Intelligence
INSERT INTO Subject (Code, Title) VALUES ('AI101', 'Introduction to AI');
INSERT INTO Subject (Code, Title) VALUES ('AI102', 'Machine Learning');
INSERT INTO Subject (Code, Title) VALUES ('AI103', 'Neural Networks');
-- For Data Science
INSERT INTO Subject (Code, Title) VALUES ('DS101', 'Introduction to Data Science');
INSERT INTO Subject (Code, Title) VALUES ('DS102', 'Statistical Methods');
INSERT INTO Subject (Code, Title) VALUES ('DS103', 'Data Visualization');
-- For Information Technology
INSERT INTO Subject (Code, Title) VALUES ('IT101', 'IT Fundamentals');
INSERT INTO Subject (Code, Title) VALUES ('IT102', 'Database Management');
INSERT INTO Subject (Code, Title) VALUES ('IT103', 'Web Technologies');

SELECT * FROM Subject

-- View result from same department only
SELECT * FROM dbo.DepartmentResults;

-- Add Result
EXEC AddResult 
	@StudentID = 'ST1001',
	@LecturerID = 'LC1001',
	@SubjectCode = 'CS101',
	@Grade = 'A+',
	@CreatedBy = 'LC1001',
	@Department = 'Computer Science';

EXEC AddResult 
	@StudentID = 'ST1003',
	@LecturerID = 'LC1001',
	@SubjectCode = 'CS102',
	@Grade = 'A+',
	@CreatedBy = 'LC1001',
	@Department = 'Computer Science';

EXEC AddResult 
	@StudentID = 'ST1006',
	@LecturerID = 'LC1001',
	@SubjectCode = 'CS103',
	@Grade = 'A+',
	@CreatedBy = 'LC1001',
	@Department = 'Computer Science';

-- Update result
EXEC dbo.UpdateResult @ResultID = 12, @Grade = 'B-', @LecturerID = 'LC1001';

-- Delete result
EXEC dbo.DeleteResult @ResultID = 12, @LecturerID = 'LC1001';

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Lecturer LC1002 - Cybersecurity
EXECUTE AS LOGIN = 'LC1002';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View Own Details
EXEC dbo.ViewOwnDetails;

EXEC dbo.UpdateLecturerDetails 
	@LecturerID = 'LC1002', 
	@NewPassword = 'Bob@1234', 
	@NewName = 'Bob Johnson', 
	@NewPhone = '011-23548896', 
	@NewDepartment = 'Cybersecurity';

-- View students info
SELECT * FROM dbo.AllStudentsInfo

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

SELECT * FROM Subject

-- View own department result
SELECT * FROM dbo.DepartmentResults;

-- Add Result
EXEC AddResult 
	@StudentID = 'ST1007',
	@LecturerID = 'LC1002',
	@SubjectCode = 'CYB101',
	@Grade = 'A',
	@CreatedBy = 'LC1002',
	@Department = 'Cybersecurity';

EXEC AddResult 
	@StudentID = 'ST1007',
	@LecturerID = 'LC1002',
	@SubjectCode = 'CYB102',
	@Grade = 'A+',
	@CreatedBy = 'LC1002',
	@Department = 'Cybersecurity';

EXEC AddResult 
	@StudentID = 'ST1010',
	@LecturerID = 'LC1002',
	@SubjectCode = 'CYB103',
	@Grade = 'A+',
	@CreatedBy = 'LC1002',
	@Department = 'Cybersecurity';

-- Update result
EXEC dbo.UpdateResult @ResultID = 12, @Grade = 'B-', @LecturerID = 'LC1002';

-- Delete result
EXEC dbo.DeleteResult @ResultID = 12, @LecturerID = 'LC1002';

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Lecturer LC1007 - Computer Science
EXECUTE AS LOGIN = 'LC1007';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View Own Details
EXEC dbo.ViewOwnDetails;

EXEC dbo.UpdateLecturerDetails 
	@LecturerID = 'LC1007', 
	@NewPassword = 'Jane@1234', 
	@NewName = 'Jane Miller', 
	@NewPhone = '018-5487762', 
	@NewDepartment = 'Computer Science';

-- View students info
SELECT * FROM dbo.AllStudentsInfo

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

SELECT * FROM Subject

-- View own department result
SELECT * FROM dbo.DepartmentResults;

EXEC AddResult 
	@StudentID = 'ST1009',
	@LecturerID = 'LC1007',
	@SubjectCode = 'CS101',
	@Grade = 'A+',
	@CreatedBy = 'LC1007',
	@Department = 'Computer Science';

EXEC AddResult 
	@StudentID = 'ST1009',
	@LecturerID = 'LC1007',
	@SubjectCode = 'CS102',
	@Grade = 'A+',
	@CreatedBy = 'LC1007',
	@Department = 'Computer Science';

EXEC AddResult 
	@StudentID = 'ST1012',
	@LecturerID = 'LC1007',
	@SubjectCode = 'CS103',
	@Grade = 'A+',
	@CreatedBy = 'LC1007',
	@Department = 'Computer Science';

-- Update result
EXEC dbo.UpdateResult @ResultID = 40, @Grade = 'A+', @LecturerID = 'LC1007';

-- Delete result
EXEC dbo.DeleteResult @ResultID = 12, @LecturerID = 'LC1007';

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Lecturer LC1003 - Software Engineering
EXECUTE AS LOGIN = 'LC1003';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View Own Details
EXEC dbo.ViewOwnDetails;

EXEC dbo.UpdateLecturerDetails 
	@LecturerID = 'LC1003', 
	@NewPassword = 'Cathy@1234', 
	@NewName = 'Cathy Brown', 
	@NewPhone = '018-5487225', 
	@NewDepartment = 'Software Engineering';

-- View students info
SELECT * FROM dbo.AllStudentsInfo

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

SELECT * FROM Subject

-- View own department result
SELECT * FROM dbo.DepartmentResults;

EXEC AddResult 
	@StudentID = 'ST1008',
	@LecturerID = 'LC1003',
	@SubjectCode = 'SE101',
	@Grade = 'A+',
	@CreatedBy = 'LC1003',
	@Department = 'Software Engineering';

EXEC AddResult 
	@StudentID = 'ST1004',
	@LecturerID = 'LC1003',
	@SubjectCode = 'SE102',
	@Grade = 'A+',
	@CreatedBy = 'LC1003',
	@Department = 'Software Engineering';

EXEC AddResult 
	@StudentID = 'ST1010',
	@LecturerID = 'LC1003',
	@SubjectCode = 'SE103',
	@Grade = 'A+',
	@CreatedBy = 'LC1003',
	@Department = 'Software Engineering';

-- Update result
EXEC dbo.UpdateResult @ResultID = 45, @Grade = 'A', @LecturerID = 'LC1003';

-- Delete result
EXEC dbo.DeleteResult @ResultID = 44, @LecturerID = 'LC1003';

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Lecturer LC1008 - Cybersecurity
EXECUTE AS LOGIN = 'LC1008';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View Own Details
EXEC dbo.ViewOwnDetails;

EXEC dbo.UpdateLecturerDetails 
	@LecturerID = 'LC1008', 
	@NewPassword = 'Mike@1234', 
	@NewName = 'Mike Barnes', 
	@NewPhone = '018-2266547', 
	@NewDepartment = 'Cybersecurity';

-- View students info
SELECT * FROM dbo.AllStudentsInfo

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

SELECT * FROM Subject

-- View own department result
SELECT * FROM dbo.DepartmentResults;

EXEC AddResult 
	@StudentID = 'ST1005',
	@LecturerID = 'LC1008',
	@SubjectCode = 'CYB101',
	@Grade = 'A+',
	@CreatedBy = 'LC1008',
	@Department = 'Cybersecurity';

EXEC AddResult 
	@StudentID = 'ST1002',
	@LecturerID = 'LC1008',
	@SubjectCode = 'CYB102',
	@Grade = 'A+',
	@CreatedBy = 'LC1008',
	@Department = 'Cybersecurity';

EXEC AddResult 
	@StudentID = 'ST1002',
	@LecturerID = 'LC1008',
	@SubjectCode = 'CYB103',
	@Grade = 'A+',
	@CreatedBy = 'LC1008',
	@Department = 'Cybersecurity';

-- Update result
EXEC dbo.UpdateResult @ResultID = 47, @Grade = 'A', @LecturerID = 'LC1008';

-- Delete result
EXEC dbo.DeleteResult @ResultID = 44, @LecturerID = 'LC1008';

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Student ST1001
EXECUTE AS LOGIN = 'ST1001';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View own details
EXEC dbo.ViewOwnDetails;

-- Update own details
EXEC dbo.UpdateStudentDetails
	@StudentID = 'ST1001',
    @NewPassword = 'John@1234',
    @NewName = 'John Doe',
    @NewPhone = '012-2148759';

-- View own result
SELECT * FROM dbo.StudentAcademicData

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Student ST1002
EXECUTE AS LOGIN = 'ST1002';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View own details
EXEC dbo.ViewOwnDetails;

-- Update own details
EXEC dbo.UpdateStudentDetails
	@StudentID = 'ST1002',
    @NewPassword = 'Aaron@1234',
    @NewName = 'Aaron Chia',
    @NewPhone = '011-21512548';

-- View own result
SELECT * FROM dbo.StudentAcademicData

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Student ST1003
EXECUTE AS LOGIN = 'ST1003';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View own details
EXEC dbo.ViewOwnDetails;

-- Update own details
EXEC dbo.UpdateStudentDetails
	@StudentID = 'ST1003',
    @NewPassword = 'Micheal@1234',
    @NewName = 'Micheal Tan',
    @NewPhone = '018-8549876';

-- View own result
SELECT * FROM dbo.StudentAcademicData

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;

-- Test for Student ST1004
EXECUTE AS LOGIN = 'ST1004';
SELECT SUSER_NAME() AS CurrentUser;

USE AIS;
GO

-- View own details
EXEC dbo.ViewOwnDetails;

-- Update own details
EXEC dbo.UpdateStudentDetails
	@StudentID = 'ST1004',
    @NewPassword = 'Stainly@1234',
    @NewName = 'Stainly',
    @NewPhone = '012-5486219';

-- View own result
SELECT * FROM dbo.StudentAcademicData

-- Rrcord login and logout activity
EXEC dbo.RecordLogin @Succeeded = 1
EXEC dbo.RecordLogout

-- Test the view created by DBAdmins
SELECT * FROM DBAdminsSchema.View_StudentDetails

REVERT;