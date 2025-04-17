import asyncio
from email import message
import src.packet_sniffer.sniffer as sniffer
import src.ml_model.model as model
import src.mitigator.mitigator as mitigator
import src.utils.database as database
from src.utils.utils import *


async def run_pipeline():
    # Step 1: Capture network packets
    print("Capturing network packets...")
    sniffer.capture_packets(
        interface="wlo1", output_file="captured_packets.csv")

    # Step 2: Perform predictions on the captured packets
    print("Running predictions...")
    model.make_predictions(input_csv="captured_packets.csv",
                           model_path='src/ml_model/rf_attacks.joblib', output_csv='predictions.csv')

    # Step 3: Apply mitigations based on predictions
    print("Applying mitigations...")
    mitigator_instance = mitigator.Mitigator()

    predictions = model.load_predictions('predictions.csv')

    for _, prediction in predictions.iterrows():
        threat_type = prediction['predictions']

        if threat_type == 'Normal':
            print("No threat detected.")

            continue

        packet_details = prediction.to_dict()
        packet_details['ip'] = retrieve_ip(packet_details['wlan.sa'])
        # Convert the row into a dictionary for the packet data
        # Handle the threat based on the prediction
        actions = await mitigator_instance.handle_threat(threat_type, packet_details)
        print(f"Actions taken for {threat_type}: {actions}")

        # Insert the threat and its details into the database
        database.insert_threat(
            threat_type=threat_type,
            packet=packet_details,
            confidence=prediction['confidence'],
            actions=actions
        )
        message = f"{threat_type} detected from {packet_details['ip']} — countermeasures deployed."
        database.insert_log(message)

    """ # Step 4: Clean up mitigations
    mitigator_instance.reset_mitigations() """


if __name__ == "__main__":
    asyncio.run(run_pipeline())
