Feature: Login with a username and password
  This performs authentication against a stored set of
  credentials using the PBKDF2 algorithm, in order to
  determine whether or not a login may happen or not.
  
Scenario: Login fails when an invalid username is used
  Given There is no user account in the database named 'joebloggs'
  When I attempt to log in with the username 'joebloggs' and the password 'secret'
  Then I should not be logged in

Scenario: Login fails with a valid username but invalid password
  Given There is a user account in the database named 'joebloggs' with password 'secret'
  When I attempt to log in with the username 'joebloggs' and the password 'wrong'
  Then I should not be logged in

Scenario: Login succeeds with a valid username and password
  Given There is a user account in the database named 'joebloggs' with password 'secret'
  When I attempt to log in with the username 'joebloggs' and the password 'secret'
  Then I should be logged in
