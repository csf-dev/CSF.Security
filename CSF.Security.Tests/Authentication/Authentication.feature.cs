// ------------------------------------------------------------------------------
//  <auto-generated>
//      This code was generated by SpecFlow (http://www.specflow.org/).
//      SpecFlow Version:1.9.0.77
//      SpecFlow Generator Version:2.0.0.0
// 
//      Changes to this file may cause incorrect behavior and will be lost if
//      the code is regenerated.
//  </auto-generated>
// ------------------------------------------------------------------------------
#region Designer generated code
#pragma warning disable
namespace CSF.Security.Tests.Authentication
{
    using TechTalk.SpecFlow;
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("TechTalk.SpecFlow", "1.0.0.0")]
    [System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    [NUnit.Framework.TestFixtureAttribute()]
    [NUnit.Framework.DescriptionAttribute("Login with a username and password")]
    public partial class LoginWithAUsernameAndPasswordFeature
    {
        
        private TechTalk.SpecFlow.ITestRunner testRunner;
        
#line 1 "Authentication.feature"
#line hidden
        
        [NUnit.Framework.TestFixtureSetUpAttribute()]
        public virtual void FeatureSetup()
        {
            testRunner = TechTalk.SpecFlow.TestRunnerManager.GetTestRunner();
            TechTalk.SpecFlow.FeatureInfo featureInfo = new TechTalk.SpecFlow.FeatureInfo(new System.Globalization.CultureInfo("en-US"), "Login with a username and password", "  This performs authentication against a stored set of\n  credentials using the PBKDF2 algorithm, in order to\n  determine whether or not a login may happen or not.", ProgrammingLanguage.CSharp, ((string[])(null)));
            testRunner.OnFeatureStart(featureInfo);
        }
        
        [NUnit.Framework.TestFixtureTearDownAttribute()]
        public virtual void FeatureTearDown()
        {
            testRunner.OnFeatureEnd();
            testRunner = null;
        }
        
        [NUnit.Framework.SetUpAttribute()]
        public virtual void TestInitialize()
        {
        }
        
        [NUnit.Framework.TearDownAttribute()]
        public virtual void ScenarioTearDown()
        {
            testRunner.OnScenarioEnd();
        }
        
        public virtual void ScenarioSetup(TechTalk.SpecFlow.ScenarioInfo scenarioInfo)
        {
            testRunner.OnScenarioStart(scenarioInfo);
        }
        
        public virtual void ScenarioCleanup()
        {
            testRunner.CollectScenarioErrors();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("Login fails when an invalid username is used")]
        public virtual void LoginFailsWhenAnInvalidUsernameIsUsed()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("Login fails when an invalid username is used", ((string[])(null)));
#line 6
this.ScenarioSetup(scenarioInfo);
#line 7
  testRunner.Given("there is no user account in the database named 'joebloggs'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 8
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 9
  testRunner.Then("I should not be logged in", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("Login fails with a valid username but invalid password")]
        public virtual void LoginFailsWithAValidUsernameButInvalidPassword()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("Login fails with a valid username but invalid password", ((string[])(null)));
#line 11
this.ScenarioSetup(scenarioInfo);
#line 12
  testRunner.Given("there is a user account in the database named 'joebloggs' with password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 13
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'wrong'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 14
  testRunner.Then("I should not be logged in", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("Login succeeds with a valid username and password")]
        public virtual void LoginSucceedsWithAValidUsernameAndPassword()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("Login succeeds with a valid username and password", ((string[])(null)));
#line 16
this.ScenarioSetup(scenarioInfo);
#line 17
  testRunner.Given("there is a user account in the database named 'joebloggs' with password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 18
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 19
  testRunner.Then("I should be logged in", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("An external service listening for success is notified when login succeeds")]
        public virtual void AnExternalServiceListeningForSuccessIsNotifiedWhenLoginSucceeds()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("An external service listening for success is notified when login succeeds", ((string[])(null)));
#line 21
this.ScenarioSetup(scenarioInfo);
#line 22
  testRunner.Given("there is a user account in the database named 'joebloggs' with password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 23
    testRunner.And("there is an external service listening for success", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "And ");
#line 24
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 25
  testRunner.Then("the external service should be notified", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("An external service listening for success is not notified when login fails")]
        public virtual void AnExternalServiceListeningForSuccessIsNotNotifiedWhenLoginFails()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("An external service listening for success is not notified when login fails", ((string[])(null)));
#line 27
this.ScenarioSetup(scenarioInfo);
#line 28
  testRunner.Given("there is a user account in the database named 'joebloggs' with password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 29
    testRunner.And("there is an external service listening for success", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "And ");
#line 30
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'wrong'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 31
  testRunner.Then("the external service should not be notified", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("An external service listening for failure is not notified when login succeeds")]
        public virtual void AnExternalServiceListeningForFailureIsNotNotifiedWhenLoginSucceeds()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("An external service listening for failure is not notified when login succeeds", ((string[])(null)));
#line 33
this.ScenarioSetup(scenarioInfo);
#line 34
  testRunner.Given("there is a user account in the database named 'joebloggs' with password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 35
    testRunner.And("there is an external service listening for failure", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "And ");
#line 36
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 37
  testRunner.Then("the external service should not be notified", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
        
        [NUnit.Framework.TestAttribute()]
        [NUnit.Framework.DescriptionAttribute("An external service listening for failure is notified when login fails")]
        public virtual void AnExternalServiceListeningForFailureIsNotifiedWhenLoginFails()
        {
            TechTalk.SpecFlow.ScenarioInfo scenarioInfo = new TechTalk.SpecFlow.ScenarioInfo("An external service listening for failure is notified when login fails", ((string[])(null)));
#line 39
this.ScenarioSetup(scenarioInfo);
#line 40
  testRunner.Given("there is a user account in the database named 'joebloggs' with password 'secret'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Given ");
#line 41
    testRunner.And("there is an external service listening for failure", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "And ");
#line 42
  testRunner.When("I attempt to log in with the username 'joebloggs' and the password 'wrong'", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "When ");
#line 43
  testRunner.Then("the external service should be notified", ((string)(null)), ((TechTalk.SpecFlow.Table)(null)), "Then ");
#line hidden
            this.ScenarioCleanup();
        }
    }
}
#pragma warning restore
#endregion
