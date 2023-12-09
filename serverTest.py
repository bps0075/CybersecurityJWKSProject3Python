import unittest
# Imported functions that to be tested
from main import StoreKeyInDatabase, GetKeysFromDatabase, StoreUser, GetUser, InsertAuthLog

class JWKSServer(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.assertNotNull = None

    # def testJWKSServerInitialization(self):
    #     self.assertNotNull()

    # def testStoreKeyInDatabase(self):
    #     # Writes a test to store a key in the database and confirm its presence
    #     self.assertNotNull(StoreKeyInDatabase())

    def testGetKeysFromDatabase(self):
        # Writes a test to get a key from the database and confirm its presence
        keys = GetKeysFromDatabase() # Works when a key is in the database
        self.assertTrue(keys)  # Check if keys exist after storing

    def testStoreUser(self):
        # Sample data used for the StoreUser function
        usernameTest = "testuser"
        passwordTest = "testpassword"
        emailTest = "testuser@example.com"

        # Store a user
        result = StoreUser(usernameTest, passwordTest, emailTest)
        self.assertTrue(result)  # Checks if the user was successfully stored

    def testGetUser(self):
        # Sample data to put using the StoreUser function to test the GetUser function
        usernameTest = "testuser"
        passwordTest = "testpassword"

        # Has to store a user first to test the GetUser function
        StoreUser(usernameTest, passwordTest, "testuser@example.com")
        # Retrieves the stored user
        storedUser = GetUser(usernameTest, passwordTest)
        self.assertIsNotNone(storedUser)  # Checks if the user was retrieved successfully
        self.assertEqual(storedUser[0], 1)  # Assuming the user ID should be 1


if __name__ == '__main__':
    unittest.main()