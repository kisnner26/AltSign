//
//  SMSChallenge.swift
//  AltSign
//

import Foundation

/// When a verification code was already sent by SMS for this sign-in (for example by an earlier attempt), Apple answers the
/// request for a new one with HTTP 412 and a JSON body describing the active challenge. That isn't a failure: the code is on its
/// way, so the caller should go on and ask the user for it.
enum SMSChallenge
{
    private struct Body: Decodable
    {
        struct PhoneNumber: Decodable { let id: Int }
        
        struct SecurityCode: Decodable
        {
            let length: Int
            let tooManyCodesSent: Bool
            let tooManyCodesValidated: Bool
            let securityCodeLocked: Bool
            let securityCodeCooldown: Bool
        }
        
        let mode: String
        let type: String
        let authenticationType: String
        let trustedPhoneNumber: PhoneNumber
        let trustedPhoneNumbers: [PhoneNumber]
        let securityCode: SecurityCode
    }
    
    /// Whether `body`, the response to a request for an SMS code for `phoneID`, describes an SMS challenge that is already active and usable.
    /// The conditions are deliberately strict (they mirror isideload's), so a 412 for any other reason, or a locked or rate limited code, still fails.
    static func isActive(statusCode: Int, body: Data, phoneID: Int) -> Bool
    {
        guard statusCode == 412, let challenge = try? JSONDecoder().decode(Body.self, from: body) else { return false }
        
        return challenge.mode == "sms" &&
            challenge.type == "verification" &&
            challenge.authenticationType == "hsa2" &&
            challenge.trustedPhoneNumber.id == phoneID &&
            challenge.trustedPhoneNumbers.contains { $0.id == phoneID } &&
            challenge.securityCode.length == 6 &&
            !challenge.securityCode.tooManyCodesSent &&
            !challenge.securityCode.tooManyCodesValidated &&
            !challenge.securityCode.securityCodeLocked &&
            !challenge.securityCode.securityCodeCooldown
    }
}
