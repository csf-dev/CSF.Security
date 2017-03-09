﻿//
// TestJsonCredentialsSerializer.cs
//
// Author:
//       Craig Fowler <craig@csf-dev.com>
//
// Copyright (c) 2017 Craig Fowler
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using CSF.Security;
using NUnit.Framework;

namespace Test.CSF
{
  [TestFixture]
  public class TestJsonCredentialsSerializer
  {
    #region tests

    [Test]
    public void Serialize_creates_expected_json()
    {
      // Arrange
      var credentials = new StubCredentials {
        InitialisationNumber = 5,
        Key = "My key",
        Salt = "Salty goodness",
      };
      var expectedJson = "Test.CSF.StubCredentials, Test.CSF:{\"Key\":\"My key\",\"Salt\":\"Salty goodness\",\"InitialisationNumber\":5}";
      var sut = new JsonCredentialsSerializer();

      // Act
      var result = sut.Serialize(credentials);

      // Assert
      Assert.AreEqual(expectedJson, result);
    }

    [Test]
    public void Deserialize_creates_expected_object()
    {
      // Arrange
      var json = "Test.CSF.StubCredentials, Test.CSF:{\"Key\":\"My key\",\"Salt\":\"Salty goodness\",\"InitialisationNumber\":5}";
      var expectedCredentials = new StubCredentials {
        InitialisationNumber = 5,
        Key = "My key",
        Salt = "Salty goodness",
      };
      var sut = new JsonCredentialsSerializer();

      // Act
      var result = sut.Deserialize(json);

      // Assert
      Assert.IsInstanceOf<StubCredentials>(result, "Type");
      var typedResult = (StubCredentials) result;
      Assert.AreEqual(expectedCredentials.InitialisationNumber, typedResult.InitialisationNumber, "InitialisationNumber");
      Assert.AreEqual(expectedCredentials.Key, typedResult.Key, "Key");
      Assert.AreEqual(expectedCredentials.Salt, typedResult.Salt, "Salt");
    }

    #endregion
  }

  public class StubCredentials
  {
    public string Key
    {
      get;
      set;
    }

    public string Salt
    {
      get;
      set;
    }

    public int InitialisationNumber
    {
      get;
      set;
    }
  }
}
