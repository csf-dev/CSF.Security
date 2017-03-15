Feature: Login with a username and password
  This performs authentication against a stored set of
  credentials using the PBKDF2 algorithm, in order to
  determine whether or not a login may happen or not.
  
Scenario: Login fails when an invalid username is used
  Given there is no user account in the database named 'joebloggs'
  When I attempt to log in with the username 'joebloggs' and the password 'secret'
  Then I should not be logged in

Scenario: Login fails with a valid username but invalid password
  Given there is a user account in the database named 'joebloggs' with password 'secret'
  When I attempt to log in with the username 'joebloggs' and the password 'wrong'
  Then I should not be logged in

Scenario: Login succeeds with a valid username and password
  Given there is a user account in the database named 'joebloggs' with password 'secret'
  When I attempt to log in with the username 'joebloggs' and the password 'secret'
  Then I should be logged in

Scenario: An external service listening for success is notified when login succeeds
  Given there is a user account in the database named 'joebloggs' with password 'secret'
    And there is an external service listening for success
  When I attempt to log in with the username 'joebloggs' and the password 'secret'
  Then the external service should be notified

Scenario: An external service listening for success is not notified when login fails
  Given there is a user account in the database named 'joebloggs' with password 'secret'
    And there is an external service listening for success
  When I attempt to log in with the username 'joebloggs' and the password 'wrong'
  Then the external service should not be notified

Scenario: An external service listening for failure is not notified when login succeeds
  Given there is a user account in the database named 'joebloggs' with password 'secret'
    And there is an external service listening for failure
  When I attempt to log in with the username 'joebloggs' and the password 'secret'
  Then the external service should not be notified

Scenario: An external service listening for failure is notified when login fails
  Given there is a user account in the database named 'joebloggs' with password 'secret'
    And there is an external service listening for failure
  When I attempt to log in with the username 'joebloggs' and the password 'wrong'
  Then the external service should be notified
