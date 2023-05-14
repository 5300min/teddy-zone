import com.amazonaws.auth.DefaultAWSCredentialsProviderChain
import com.amazonaws.client.builder.AwsClientBuilder
import com.amazonaws.regions.DefaultAwsRegionProviderChain
import com.amazonaws.services.iot.AWSIot
import com.amazonaws.services.iot.AWSIotClientBuilder
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest
import com.amazonaws.services.iot.model.AttachThingPrincipalRequest
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult
import com.amazonaws.services.iot.model.CreatePolicyRequest
import com.amazonaws.services.iot.model.CreatePolicyResult
import com.amazonaws.services.iot.model.CreateThingRequest
import com.amazonaws.services.iot.model.CreateThingResult
import com.amazonaws.services.iot.model.DeletePolicyRequest
import com.amazonaws.services.iot.model.DetachPrincipalPolicyRequest
import com.amazonaws.services.iot.model.GetPolicyRequest
import com.amazonaws.services.iot.model.ListPoliciesRequest
import com.amazonaws.services.iot.model.ListPrincipalPoliciesRequest
import com.amazonaws.services.iotdata.AWSIotData
import com.amazonaws.services.iotdata.AWSIotDataClientBuilder
import com.amazonaws.services.iotdata.model.PublishRequest
import java.nio.ByteBuffer

fun createIotData(): AWSIotData {
    val endpoint = "a1k7w1nfe5d92z-ats.iot.ap-northeast-2.amazonaws.com"

    return AWSIotDataClientBuilder.standard()
        .withCredentials(DefaultAWSCredentialsProviderChain())
        .withEndpointConfiguration(AwsClientBuilder.EndpointConfiguration(
            endpoint, DefaultAwsRegionProviderChain().region
        )).build()
}

fun publish(message: String) {
    val iotData = createIotData()

    val messege = """
        {
            "messege" : "$message"
        }
    """.trimIndent()

    val request = PublishRequest().apply {
        withTopic("test/topic")
        withPayload(ByteBuffer.wrap(messege.toByteArray()))
    }

    iotData.publish(request)
}

fun createThingAndCertificate(thingName: String): CreateKeysAndCertificateResult {
    val iotClient: AWSIot = AWSIotClientBuilder.defaultClient()

    // Create a new Thing
    val createThingRequest = CreateThingRequest()
        .withThingName(thingName)
    val createThingResult: CreateThingResult = iotClient.createThing(createThingRequest)

    // Create a new certificate and key pair
    val createKeysAndCertificateRequest = CreateKeysAndCertificateRequest().withSetAsActive(true)
    val createKeysAndCertificateResult: CreateKeysAndCertificateResult =
        iotClient.createKeysAndCertificate(createKeysAndCertificateRequest)

    // Attach the certificate to the Thing
    val attachThingPrincipalRequest = AttachThingPrincipalRequest()
        .withThingName(thingName)
        .withPrincipal(createKeysAndCertificateResult.certificateArn)
    iotClient.attachThingPrincipal(attachThingPrincipalRequest)

    // Check if a policy with the same name already exists
    val listPoliciesRequest = ListPoliciesRequest()
    val listPoliciesResult = iotClient.listPolicies(listPoliciesRequest)
    for (policy in listPoliciesResult.policies) {
        if (policy.policyName == thingName) {
            // Delete the existing policy
            val deletePolicyRequest = DeletePolicyRequest()
                .withPolicyName(policy.policyName)
            iotClient.deletePolicy(deletePolicyRequest)
        }
    }

    // Create a new policy
    val policyName = thingName
    val policyDocument = getPolicyDocument(thingName)
    val createPolicyRequest = CreatePolicyRequest()
        .withPolicyName(policyName)
        .withPolicyDocument(policyDocument)
    val createPolicyResult: CreatePolicyResult = iotClient.createPolicy(createPolicyRequest)

    // Detach all existing policies from the certificate
    val listPrincipalPoliciesRequest = ListPrincipalPoliciesRequest()
        .withPrincipal(createKeysAndCertificateResult.certificateArn)
    val listPrincipalPoliciesResult = iotClient.listPrincipalPolicies(listPrincipalPoliciesRequest)
    for (policy in listPrincipalPoliciesResult.policies) {
        val detachPrincipalPolicyRequest = DetachPrincipalPolicyRequest()
            .withPolicyName(policy.policyName)
            .withPrincipal(createKeysAndCertificateResult.certificateArn)
        iotClient.detachPrincipalPolicy(detachPrincipalPolicyRequest)
    }

    // Attach the new policy to the certificate
    val attachPrincipalPolicyRequest = AttachPrincipalPolicyRequest()
        .withPolicyName(policyName)
        .withPrincipal(createKeysAndCertificateResult.certificateArn)
    iotClient.attachPrincipalPolicy(attachPrincipalPolicyRequest)

    println(">>> createThingResult - arn : ${createThingResult.thingArn}")
    println(">>> createKeysAndCertificateResult - arn : ${createKeysAndCertificateResult.certificateArn}")
    println(">>> createKeysAndCertificateResult - certificateId : ${createKeysAndCertificateResult.certificateId}")
    println(">>> createKeysAndCertificateResult - certificatePem : ${createKeysAndCertificateResult.certificatePem}")
    println(">>> createKeysAndCertificateResult - publicKey : ${createKeysAndCertificateResult.keyPair.publicKey}")
    println(">>> createKeysAndCertificateResult - privateKey : ${createKeysAndCertificateResult.keyPair.privateKey}")

    return createKeysAndCertificateResult
}

private fun getPolicyDocument(thingsName: String) = """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iot:Connect",
                "Resource": "arn:aws:iot:ap-northeast-2:366014620146:client/*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "iot:Publish",
                    "iot:Receive"
                ],
                "Resource": "arn:aws:iot:ap-northeast-2:366014620146:topic/*"
            },
            {
                "Effect": "Allow",
                "Action": "iot:Subscribe",
                "Resource": [
                    "arn:aws:iot:ap-northeast-2:366014620146:topicfilter/pos",
                    "arn:aws:iot:ap-northeast-2:366014620146:topicfilter/pos2",
                    "arn:aws:iot:ap-northeast-2:366014620146:topicfilter/device/${thingsName}"
                ]
            }
        ]
    }
""".trimIndent()

fun main() {
//    publish("test Hello")

    createThingAndCertificate("test_thing8")
}
