using System;
using CSF.Security.Tests.Controllers;
using NUnit.Framework;
using TechTalk.SpecFlow;

namespace CSF.Security.Tests.Bindings
{
  [Binding]
  public class AuthenticationSteps
  {
    #region fields

    readonly UserAccountController userAccountController;
    readonly AuthenticationController authenticationController;

    #endregion

    #region steps

    [Given("there is no user account in the database named '([^']+)'")]
    public void GivenThereIsNoUserAccount(string username)
    {
      userAccountController.SetupNoUserAccount(username);
    }

    [Given("there is a user account in the database named '([^']+)' with password '([^']+)'")]
    public void GivenThereIsAUserAccount(string username, string password)
    {
      userAccountController.SetupUserAccount(username, password);
    }

    [Given("there is an external service listening for ([^ ]+)")]
    public void GivenAnExternalServiceIsListening(string eventName)
    {
      switch(eventName)
      {
      case "success":
        authenticationController.SetupSuccessListener();
        break;
      case "failure":
        authenticationController.SetupFailureListener();
        break;
      }
    }

    [When("I attempt to log in with the username '([^']+)' and the password '([^']+)'")]
    public void WhenIAttemptToLogIn(string username, string password)
    {
      authenticationController.AttemptLogin(username, password, userAccountController.Repository);
    }

    [Then("I should be logged in")]
    public void ThenIShouldBeLoggedIn()
    {
      Assert.NotNull(authenticationController.AuthenticationResult, "Authentication result must not be null");
      Assert.IsTrue(authenticationController.AuthenticationResult.Success, "Authentication result must indicate success");
    }

    [Then("I should not be logged in")]
    public void ThenIShouldNotBeLoggedIn()
    {
      Assert.NotNull(authenticationController.AuthenticationResult, "Authentication result must not be null");
      Assert.IsFalse(authenticationController.AuthenticationResult.Success, "Authentication result must indicate failure");
    }

    [Then("the external service should be notified")]
    public void ThenTheServiceShouldBeNotified()
    {
      Assert.IsTrue(authenticationController.ListenerWasTriggered);
    }

    [Then("the external service should not be notified")]
    public void ThenTheServiceShouldNotBeNotified()
    {
      Assert.IsFalse(authenticationController.ListenerWasTriggered);
    }

    #endregion

    #region constructor

    public AuthenticationSteps(UserAccountController userAccountController,
                               AuthenticationController authenticationController)
    {
      if(authenticationController == null)
        throw new ArgumentNullException(nameof(authenticationController));
      if(userAccountController == null)
        throw new ArgumentNullException(nameof(userAccountController));

      this.userAccountController = userAccountController;
      this.authenticationController = authenticationController;
    }

    #endregion
  }
}
