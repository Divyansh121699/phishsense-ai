#!/bin/bash

#SBATCH --job-name=phish_roberta
#SBATCH --account=storabi
#SBATCH --partition=gpuq
#SBATCH --qos=gpu
#SBATCH --gres=gpu:1g.10gb:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=roberta_%j.out
#SBATCH --error=roberta_%j.err

echo "=================================================="
echo "PhishSense AI - RoBERTa Preliminary 3000 Run"
echo "Job ID: $SLURM_JOB_ID"
echo "Node: $(hostname)"
echo "Started: $(date)"
echo "=================================================="

cd ~/phishsense-ai || exit 1

module purge
module load hosts/hopper
module load gnu/12.3.0
module load python/3.11.7-cx

source ~/phishsense-ai/venv_hopper/bin/activate

echo
echo "Python:"
which python
python --version

echo
echo "GPU:"
nvidia-smi

echo
echo "PyTorch CUDA check:"
python -c "import torch; print('CUDA available:', torch.cuda.is_available()); print('GPU:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'None'); print('PyTorch CUDA:', torch.version.cuda)"

echo
echo "Starting RoBERTa training..."
echo

python training/models/roberta/train.py \
    --dataset data/sample/preliminary_3000.csv \
    --splits data/sample/preliminary_3000_splits.csv

EXIT_CODE=$?

echo
echo "=================================================="
echo "Finished: $(date)"
echo "Exit code: $EXIT_CODE"
echo "=================================================="

exit $EXIT_CODE
