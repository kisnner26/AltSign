# Runs the production SMS method with a scripted transport; no Apple credentials or network calls.
require 'open3'

source = File.read(File.join(__dir__, '../AltSign/Sources/ALTAppleAPI+Authentication.swift'))
method = source[/    func requestSMSTwoFactorCode\(.*?(?=    func fetchAccount\()/m]
abort 'SMS method not found' unless method

harness = <<~SWIFT
  import Foundation
  struct ALTAnisetteData {}
  struct ALTAppleAPIError: Error {
      enum Code { case requiresTwoFactorAuthentication, incorrectVerificationCode }
      let code: Code?
      let status: Int?
      init(_ code: Code) { self.code = code; status = nil }
      static func unknown(statusCode: Int, failure: String) -> Self {
          Self(code: nil, status: statusCode)
      }
      private init(code: Code?, status: Int?) { self.code = code; self.status = status }
  }
  enum TransportError: Error { case offline }
  final class Harness {
      var responses: [Result<(Data, HTTPURLResponse), Error>] = []
      var requests: [URLRequest] = []
      func makeTwoFactorCodeRequest(url: URL, dsid: String, idmsToken: String,
                                   anisetteData: ALTAnisetteData) -> URLRequest {
          var request = URLRequest(url: url)
          request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
          request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
          return request
      }
      func sendGSARequest(_ request: URLRequest,
          completionHandler: @escaping (Result<(Data, HTTPURLResponse), Error>) -> Void) {
          requests.append(request)
          precondition(!responses.isEmpty)
          completionHandler(responses.removeFirst())
      }
  #{method}
  }
  func response(_ status: Int, token: Bool = false) -> Result<(Data, HTTPURLResponse), Error> {
      .success((Data(), HTTPURLResponse(url: URL(string: "https://gsa.apple.com")!,
          statusCode: status, httpVersion: nil,
          headerFields: token ? ["X-Apple-PE-Token": "test"] : [:])!))
  }
  func run(_ name: String, _ responses: [Result<(Data, HTTPURLResponse), Error>],
           code: String? = "123456", expectedRequests: Int, expectedSuccess: Bool,
           expectedPrompts: Int) {
      let harness = Harness()
      harness.responses = responses
      var completions = 0
      var prompts = 0
      harness.requestSMSTwoFactorCode(dsid: "test", idmsToken: "test",
          anisetteData: ALTAnisetteData(), verificationHandler: { callback in
              prompts += 1
              callback(code)
          }, completionHandler: { result in
              completions += 1
              switch result {
              case .success: precondition(expectedSuccess, name)
              case .failure: precondition(!expectedSuccess, name)
              }
          })
      precondition(completions == 1 && prompts == expectedPrompts, name)
      precondition(harness.requests.count == expectedRequests, name)
      for (index, request) in harness.requests.enumerated() {
          precondition(request.httpMethod == (index == 0 ? "PUT" : "POST"))
          precondition(request.url?.path == (index == 0 ? "/auth/verify/phone" : "/auth/verify/phone/securitycode"))
          precondition(request.url?.query == nil)
          precondition(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
          precondition(request.value(forHTTPHeaderField: "Accept") == "application/json")
          let body = try! JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any]
          precondition((body["phoneNumber"] as? [String: Int])?["id"] == 1)
          precondition(body["mode"] as? String == "sms")
          if index == 1 {
              precondition((body["securityCode"] as? [String: String])?["code"] == code)
          }
      }
      print("passed: \\(name)")
  }
  run("success", [response(200), response(200, token: true)], expectedRequests: 2, expectedSuccess: true, expectedPrompts: 1)
  run("delivery HTTP 415", [response(415)], expectedRequests: 1, expectedSuccess: false, expectedPrompts: 0)
  run("delivery transport error", [.failure(TransportError.offline)], expectedRequests: 1, expectedSuccess: false, expectedPrompts: 0)
  run("cancel code entry", [response(200)], code: nil, expectedRequests: 1, expectedSuccess: false, expectedPrompts: 1)
  run("rejected code", [response(200), response(403)], expectedRequests: 2, expectedSuccess: false, expectedPrompts: 1)
  run("missing PE token", [response(200), response(200)], expectedRequests: 2, expectedSuccess: false, expectedPrompts: 1)
  run("verification transport error", [response(200), .failure(TransportError.offline)], expectedRequests: 2, expectedSuccess: false, expectedPrompts: 1)
SWIFT
stdout, stderr, status = Open3.capture3('swift', '-', stdin_data: harness)
puts stdout
warn stderr unless stderr.empty?
exit(status.success? ? 0 : 1)
